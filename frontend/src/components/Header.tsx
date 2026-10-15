import type { GraphOverview, HealthResponse } from '../api';
import { FALKORDB_BROWSER_URL } from '../api';
import type { GraphSnapshot } from '../events';
import { formatCount } from '../lib/json';

interface Props {
  health: HealthResponse | null;
  healthError: string | null;
  overview: GraphOverview | null;
  snapshot: GraphSnapshot | null;
  mock: boolean;
  reseeding: boolean;
  /** A run is in progress: reseeding would pull the graph out from under the agent. */
  running: boolean;
  onReseed: () => void;
}

function BrandMark() {
  return (
    <svg className="brand__mark" viewBox="0 0 32 32" width="26" height="26" aria-hidden="true">
      <path
        d="M16 2 L28 7 V16 C28 23 22.5 28.5 16 30 C9.5 28.5 4 23 4 16 V7 Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <path d="M11 20 L16 11 L21 20 H11" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" opacity="0.6" />
      <circle cx="16" cy="11" r="2.6" fill="#ff4d5e" />
      <circle cx="11" cy="20" r="2.4" fill="#38d996" />
      <circle cx="21" cy="20" r="2.4" fill="#ffb020" />
    </svg>
  );
}

export default function Header({ health, healthError, overview, snapshot, mock, reseeding, running, onReseed }: Props) {
  const dbTone = health?.falkordb ? 'ok' : healthError || health ? 'bad' : 'idle';
  const dbText = health?.falkordb
    ? 'FalkorDB connected'
    : healthError
      ? 'FalkorDB unreachable'
      : health
        ? 'FalkorDB degraded'
        : 'Checking FalkorDB';
  const modeText = !health ? 'Agent mode unknown' : health.llm_configured
      ? `LLM agent · ${health.llm_provider === 'openrouter' ? 'OpenRouter' : 'Claude'} (${health.model ?? 'model unset'})`
      : 'Deterministic agent';

  const prodEntry = overview?.graphs.find((g) => g.kind === 'prod');
  const nodeCount = snapshot?.nodes.length ?? prodEntry?.nodes;
  const edgeCount = snapshot?.edges.length ?? prodEntry?.edges;
  const sandboxCount = overview?.graphs.filter((g) => g.kind === 'sandbox').length ?? 0;

  return (
    <header className="topbar">
      <div className="brand">
        <BrandMark />
        <div>
          <div className="brand__name">AegisGraph</div>
          <div className="brand__tag">Graph-grounded incident remediation</div>
        </div>
      </div>

      <div className="topbar__status" aria-live="polite">
        <span className={`pill pill--${dbTone}`} title={healthError ?? undefined}>
          <i className="pill__dot" />
          {dbText}
        </span>
        <span className="pill pill--plain">{modeText}</span>
        {mock ? (
          <span className="pill pill--warn" title="Opened with ?mock=1: no backend calls are made">
            <i className="pill__dot" />
            Mock data
          </span>
        ) : null}
      </div>

      <div className="topbar__right">
        <div className="counts">
          {nodeCount !== undefined && edgeCount !== undefined ? (
            <>
              <span>
                <b>{formatCount(nodeCount)}</b> nodes
              </span>
              <span>
                <b>{formatCount(edgeCount)}</b> edges
              </span>
              {sandboxCount > 0 ? (
                <span>
                  <b>{sandboxCount}</b> sandbox{sandboxCount === 1 ? '' : 'es'}
                </span>
              ) : null}
            </>
          ) : (
            <span>graph not loaded</span>
          )}
        </div>
        <a className="btn btn--ghost" href={health?.falkordb_browser_url || FALKORDB_BROWSER_URL} target="_blank" rel="noreferrer">
          <span>FalkorDB Browser</span>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.7 }}>
            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
            <polyline points="15 3 21 3 21 9" />
            <line x1="10" y1="14" x2="21" y2="3" />
          </svg>
        </a>
        <button type="button" className="btn btn--outline" onClick={onReseed} disabled={reseeding || running} title={running ? 'Wait for the current run to finish' : undefined}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.8 }}>
            <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
          </svg>
          <span>{reseeding ? 'Reseeding…' : 'Reseed graph'}</span>
        </button>
      </div>
    </header>
  );
}
