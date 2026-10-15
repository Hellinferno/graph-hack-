import { NODE_LABELS } from '../events';
import { EDGE_SEVERED_COLOR, HIGHLIGHT_COLORS, LABEL_COLORS } from '../lib/graphStyle';

export default function Legend() {
  return (
    <div className="legend" aria-label="Graph legend">
      <div className="legend__group">
        {NODE_LABELS.map((label) => (
          <span key={label} className="legend__item">
            <i className="legend__dot" style={{ background: LABEL_COLORS[label] }} />
            {label}
          </span>
        ))}
      </div>
      <div className="legend__group legend__group--edges">
        <span className="legend__item">
          <i className="legend__line" />
          active edge
        </span>
        <span className="legend__item">
          <i className="legend__line legend__line--dashed" style={{ borderColor: EDGE_SEVERED_COLOR }} />
          isolated / quarantined
        </span>
        <span className="legend__item">
          <i className="legend__line legend__line--thick" style={{ borderColor: HIGHLIGHT_COLORS.attack }} />
          attack path
        </span>
        <span className="legend__item">
          <i className="legend__ring" style={{ borderColor: HIGHLIGHT_COLORS.chokepoint }} />
          chokepoint
        </span>
        <span className="legend__item">
          <i className="legend__line" style={{ borderColor: HIGHLIGHT_COLORS.safe }} />
          critical flow
        </span>
        <span className="legend__item">
          <i className="legend__ring" style={{ borderColor: HIGHLIGHT_COLORS.proof }} />
          proof
        </span>
        <span className="legend__hint">service size follows rps</span>
      </div>
    </div>
  );
}
