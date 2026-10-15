import type { GraphNode, HighlightStyle } from '../events';
import { HIGHLIGHT_COLORS, HIGHLIGHT_LABELS, nodeColor } from '../lib/graphStyle';

interface Props {
  node: GraphNode;
  highlight: HighlightStyle | undefined;
  degree: { inbound: number; outbound: number };
  onClose: () => void;
}

function renderValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

export default function NodeDetails({ node, highlight, degree, onClose }: Props) {
  const entries = Object.entries(node.properties);
  return (
    <aside className="node-details" aria-label={`Details for ${node.name}`}>
      <header className="node-details__head">
        <span className="node-details__swatch" style={{ background: nodeColor(node.labels) }} />
        <div className="node-details__title">
          <div className="node-details__name">{node.name}</div>
          <div className="node-details__labels">
            {node.labels.join(', ')}
            {highlight ? (
              <span className="node-details__highlight" style={{ color: HIGHLIGHT_COLORS[highlight] }}>
                {HIGHLIGHT_LABELS[highlight]}
              </span>
            ) : null}
          </div>
        </div>
        <button type="button" className="btn btn--small btn--ghost" onClick={onClose} aria-label="Close details">
          Close
        </button>
      </header>
      <dl className="props">
        {entries.map(([key, value]) => (
          <div key={key} className="props__row">
            <dt>{key}</dt>
            <dd className={typeof value === 'number' ? 'mono' : ''}>{renderValue(value)}</dd>
          </div>
        ))}
        <div className="props__row">
          <dt>edges</dt>
          <dd>
            {degree.inbound} in, {degree.outbound} out
          </dd>
        </div>
      </dl>
    </aside>
  );
}
