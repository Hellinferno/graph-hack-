import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import type { ForceGraphMethods, LinkObject, NodeObject } from 'react-force-graph-2d';
import type { EdgeStatus, GraphEdge, GraphHighlightEvent, GraphId, GraphNode, GraphSnapshot, JsonObject, NodeLabel } from '../events';
import {
  EDGE_ACTIVE_COLOR,
  EDGE_SEVERED_COLOR,
  HIGHLIGHT_COLORS,
  buildHighlightIndex,
  edgeStatus,
  isSevered,
  lookupEdgeStyle,
  nodeColor,
  primaryLabel,
  serviceRadius,
} from '../lib/graphStyle';
import { asNumber, asString } from '../lib/json';
import Legend from './Legend';
import NodeDetails from './NodeDetails';

interface GNode {
  id: string;
  name: string;
  label: NodeLabel | null;
  labels: string[];
  properties: JsonObject;
  radius: number;
  color: string;
  hollow: boolean;
  raw: GraphNode;
}

interface GLink {
  id: string;
  type: string;
  status: EdgeStatus;
  srcName: string;
  dstName: string;
  directed: boolean;
  raw: GraphEdge;
}

type FGNode = NodeObject<GNode>;
type FGLink = LinkObject<GNode, GLink>;
type FGMethods = ForceGraphMethods<NodeObject<GNode>, LinkObject<GNode, GLink>>;

interface Props {
  snapshot: GraphSnapshot | null;
  loading: boolean;
  error: string | null;
  highlights: GraphHighlightEvent[];
  selectedNodeId: GraphId | null;
  onSelectNode: (node: GraphNode | null) => void;
  viewingSandbox: boolean;
  onBackToProduction: () => void;
}

const DIRECTED_EDGES = new Set(['ROUTES_TO', 'ASSUMES_ROLE', 'CAN_ACCESS', 'CALLS', 'IMPORTS', 'AFFECTS']);
const TWO_PI = Math.PI * 2;

function buildData(snapshot: GraphSnapshot, previous: FGNode[]): { nodes: FGNode[]; links: FGLink[] } {
  const positions = new Map(previous.map((n) => [n.name, { x: n.x, y: n.y, vx: n.vx, vy: n.vy }]));
  const nodes: FGNode[] = snapshot.nodes.map((raw) => {
    const label = primaryLabel(raw.labels);
    const status = asString(raw.properties.status);
    const node: FGNode = {
      id: String(raw.id),
      name: raw.name,
      label,
      labels: raw.labels,
      properties: raw.properties,
      radius: label === 'Service' ? serviceRadius(asNumber(raw.properties.rps)) : label === 'Database' || label === 'IAMRole' ? 5.5 : label === 'Incident' || label === 'Vulnerability' ? 5 : 4,
      color: nodeColor(raw.labels),
      hollow: status === 'ISOLATED' || status === 'QUARANTINED',
      raw,
    };
    const prev = positions.get(raw.name);
    if (prev && prev.x !== undefined && prev.y !== undefined) {
      node.x = prev.x;
      node.y = prev.y;
      node.vx = prev.vx;
      node.vy = prev.vy;
    }
    return node;
  });
  const nameById = new Map(snapshot.nodes.map((n) => [String(n.id), n.name]));
  const links: FGLink[] = snapshot.edges
    .filter((e) => nameById.has(String(e.src_id)) && nameById.has(String(e.dst_id)))
    .map((raw) => ({
      id: String(raw.id),
      type: raw.type,
      status: edgeStatus(raw.properties),
      srcName: nameById.get(String(raw.src_id)) ?? '',
      dstName: nameById.get(String(raw.dst_id)) ?? '',
      directed: DIRECTED_EDGES.has(raw.type),
      source: String(raw.src_id),
      target: String(raw.dst_id),
      raw,
    }));
  return { nodes, links };
}

const HTML_ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (ch) => HTML_ESCAPES[ch]);
}

export default function GraphView({ snapshot, loading, error, highlights, selectedNodeId, onSelectNode, viewingSandbox, onBackToProduction }: Props) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const graphRef = useRef<FGMethods | undefined>(undefined);
  const previousNodes = useRef<FGNode[]>([]);
  const [size, setSize] = useState({ width: 0, height: 0 });

  useLayoutEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => setSize({ width: el.clientWidth, height: el.clientHeight });
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const data = useMemo(() => {
    if (!snapshot) return { nodes: [] as FGNode[], links: [] as FGLink[] };
    return buildData(snapshot, previousNodes.current);
  }, [snapshot]);

  useEffect(() => {
    previousNodes.current = data.nodes;
    const timer = window.setTimeout(() => graphRef.current?.zoomToFit(600, 48), 700);
    return () => window.clearTimeout(timer);
  }, [data]);

  useEffect(() => {
    const graph = graphRef.current;
    if (!graph) return;
    const charge = graph.d3Force('charge') as ({ strength?: (value: number) => unknown } & object) | undefined;
    charge?.strength?.(-240);
    const link = graph.d3Force('link') as ({ distance?: (value: number) => unknown } & object) | undefined;
    link?.distance?.(52);
  }, [data]);

  const index = useMemo(() => buildHighlightIndex(highlights), [highlights]);
  const selectedId = selectedNodeId === null ? null : String(selectedNodeId);
  const latest = highlights.length > 0 ? highlights[highlights.length - 1] : null;

  const selectedNode = useMemo(() => {
    if (selectedId === null || !snapshot) return null;
    return snapshot.nodes.find((n) => String(n.id) === selectedId) ?? null;
  }, [selectedId, snapshot]);

  const selectedDegree = useMemo(() => {
    if (!selectedNode || !snapshot) return { inbound: 0, outbound: 0 };
    let inbound = 0;
    let outbound = 0;
    for (const e of snapshot.edges) {
      if (String(e.src_id) === String(selectedNode.id)) outbound += 1;
      if (String(e.dst_id) === String(selectedNode.id)) inbound += 1;
    }
    return { inbound, outbound };
  }, [selectedNode, snapshot]);

  const drawNode = useCallback(
    (node: FGNode, ctx: CanvasRenderingContext2D, scale: number) => {
      const x = node.x ?? 0;
      const y = node.y ?? 0;
      const r = node.radius;
      const style = index.nodes.get(node.name);

      if (style) {
        ctx.beginPath();
        ctx.arc(x, y, r + 4, 0, TWO_PI);
        ctx.strokeStyle = HIGHLIGHT_COLORS[style];
        ctx.lineWidth = style === 'chokepoint' ? 3 : 2;
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(x, y, r + 9, 0, TWO_PI);
        ctx.fillStyle = `${HIGHLIGHT_COLORS[style]}22`;
        ctx.fill();
      }
      if (selectedId === node.id) {
        ctx.beginPath();
        ctx.arc(x, y, r + 7, 0, TWO_PI);
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 1;
        ctx.setLineDash([2, 2]);
        ctx.stroke();
        ctx.setLineDash([]);
      }

      ctx.beginPath();
      ctx.arc(x, y, r, 0, TWO_PI);
      if (node.hollow) {
        ctx.fillStyle = '#0c131c';
        ctx.fill();
        ctx.strokeStyle = node.color;
        ctx.lineWidth = 1.6;
        ctx.setLineDash([3, 2]);
        ctx.stroke();
        ctx.setLineDash([]);
      } else {
        ctx.fillStyle = node.color;
        ctx.fill();
      }

      const alwaysLabel = node.label === 'Service' || node.label === 'Database' || node.label === 'IAMRole' || !!style || selectedId === node.id;
      if (alwaysLabel || scale > 1.6) {
        const fontSize = Math.max(11 / scale, 2.4);
        ctx.font = `500 ${fontSize}px Barlow, "Segoe UI", sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        // dark halo keeps overlapping labels legible over edges and other labels
        ctx.lineJoin = 'round';
        ctx.lineWidth = Math.max(3 / scale, 0.8);
        ctx.strokeStyle = 'rgba(12, 19, 28, 0.92)';
        ctx.strokeText(node.name, x, y + r + 2.5);
        ctx.fillStyle = style ? '#f2f6fa' : 'rgba(217, 227, 238, 0.82)';
        ctx.fillText(node.name, x, y + r + 2.5);
      }
    },
    [index, selectedId],
  );

  const paintPointerArea = useCallback((node: FGNode, color: string, ctx: CanvasRenderingContext2D) => {
    ctx.beginPath();
    ctx.arc(node.x ?? 0, node.y ?? 0, node.radius + 5, 0, TWO_PI);
    ctx.fillStyle = color;
    ctx.fill();
  }, []);

  const styleOf = useCallback((link: FGLink) => lookupEdgeStyle(index, link.srcName, link.dstName, link.type), [index]);

  const linkColor = useCallback(
    (link: FGLink) => {
      const style = styleOf(link);
      if (style) return HIGHLIGHT_COLORS[style];
      return isSevered(link.status) ? EDGE_SEVERED_COLOR : EDGE_ACTIVE_COLOR;
    },
    [styleOf],
  );
  const linkWidth = useCallback(
    (link: FGLink) => {
      const style = styleOf(link);
      if (style === 'attack') return 2.4;
      if (style) return 1.8;
      return isSevered(link.status) ? 1.4 : 0.7;
    },
    [styleOf],
  );
  const linkDash = useCallback(
    (link: FGLink) => (isSevered(link.status) || styleOf(link) === 'quarantined' ? [4, 3] : null),
    [styleOf],
  );
  const linkParticles = useCallback((link: FGLink) => (styleOf(link) === 'attack' ? 4 : 0), [styleOf]);
  const arrowLength = useCallback((link: FGLink) => (link.directed ? 4 : 0), []);
  // force-graph renders tooltip strings as HTML, so every value from the graph is escaped first
  const nodeTooltip = useCallback((node: FGNode) => escapeHtml(`${node.label ?? node.labels.join('/')}: ${node.name}`), []);
  const linkTooltip = useCallback(
    (link: FGLink) => escapeHtml(`${link.srcName} —${link.type}→ ${link.dstName}${link.status !== 'ACTIVE' ? ` (${link.status})` : ''}`),
    [],
  );

  return (
    <div className="graph" ref={containerRef}>
      {size.width > 0 && size.height > 0 && snapshot ? (
        <ForceGraph2D<GNode, GLink>
          ref={graphRef}
          width={size.width}
          height={size.height}
          graphData={data}
          backgroundColor="rgba(0,0,0,0)"
          nodeCanvasObjectMode={() => 'replace'}
          nodeCanvasObject={drawNode}
          nodePointerAreaPaint={paintPointerArea}
          nodeLabel={nodeTooltip}
          nodeVal={(node) => node.radius}
          linkLabel={linkTooltip}
          linkColor={linkColor}
          linkWidth={linkWidth}
          linkLineDash={linkDash}
          linkDirectionalArrowLength={arrowLength}
          linkDirectionalArrowRelPos={1}
          linkDirectionalArrowColor={linkColor}
          linkDirectionalParticles={linkParticles}
          linkDirectionalParticleWidth={3.2}
          linkDirectionalParticleSpeed={0.007}
          linkDirectionalParticleColor={() => HIGHLIGHT_COLORS.attack}
          linkCurvature={0.08}
          d3VelocityDecay={0.32}
          cooldownTime={6000}
          onNodeClick={(node) => onSelectNode(node.raw)}
          onBackgroundClick={() => onSelectNode(null)}
        />
      ) : null}

      <div className="graph__title">
        <div className="graph__kicker">{viewingSandbox ? 'Sandbox graph' : 'Production graph'}</div>
        <div className="graph__name mono">{snapshot?.graph ?? (loading ? 'loading…' : 'no graph')}</div>
        {viewingSandbox ? (
          <button type="button" className="btn btn--small" onClick={onBackToProduction}>
            Back to production graph
          </button>
        ) : null}
        {latest ? (
          <div className="graph__ticker" style={{ borderColor: HIGHLIGHT_COLORS[latest.style] }}>
            {latest.label}
          </div>
        ) : null}
      </div>

      {loading ? <div className="graph__state">Loading graph…</div> : null}
      {!loading && error ? <div className="graph__state graph__state--error">{error}</div> : null}
      {!loading && !error && snapshot && snapshot.nodes.length === 0 ? (
        <div className="graph__state">The graph is empty. Reseed to load the demo dataset.</div>
      ) : null}

      <Legend />
      {selectedNode ? (
        <NodeDetails node={selectedNode} highlight={index.nodes.get(selectedNode.name)} degree={selectedDegree} onClose={() => onSelectNode(null)} />
      ) : null}
    </div>
  );
}
