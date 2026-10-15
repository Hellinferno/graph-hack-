import type { MemoryOverview } from '../api';
import { formatEpoch } from '../lib/json';

interface Props {
  memory: MemoryOverview | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
}

export default function MemoryPanel({ memory, loading, error, onRefresh }: Props) {
  const counts = memory ? Object.entries(memory.counts) : [];
  return (
    <>
      <section className="section">
        <header className="section__head">
          <h2 className="section__title">Agent memory</h2>
          <button type="button" className="btn btn--small btn--ghost" onClick={onRefresh} disabled={loading}>
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </header>
        <p className="muted small">
          Episodic and procedural memory persisted in the <span className="mono">{memory?.graph ?? 'memory'}</span> graph: every run becomes an episode, every passing
          simulation becomes evidence, and successful actions become playbooks.
        </p>
        {error ? <p className="inline-error">{error}</p> : null}
        {counts.length > 0 ? (
          <div className="chips">
            {counts.map(([key, value]) => (
              <span key={key} className="chip">
                <b>{value}</b> {key}
              </span>
            ))}
          </div>
        ) : null}
      </section>

      <section className="section">
        <header className="section__head">
          <h2 className="section__title">Playbooks</h2>
          <span className="section__hint">{memory?.playbooks.length ?? 0}</span>
        </header>
        {memory && memory.playbooks.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>Signature</th>
                <th>Bridge</th>
                <th>Role</th>
                <th className="num">Wins</th>
                <th>Last used</th>
              </tr>
            </thead>
            <tbody>
              {memory.playbooks.map((p) => (
                <tr key={p.signature}>
                  <td className="mono small">{p.signature}</td>
                  <td>{p.bridge_service}</td>
                  <td>{p.iam_role}</td>
                  <td className="num">{p.success_count}</td>
                  <td className="small muted">
                    {formatEpoch(p.last_used)}
                    {p.last_incident_id ? <span className="mono"> {p.last_incident_id}</span> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="empty">No playbooks yet. A successful remediation records one keyed by the affected package.</p>
        )}
      </section>

      <section className="section">
        <header className="section__head">
          <h2 className="section__title">Episodes</h2>
          <span className="section__hint">{memory?.episodes.length ?? 0}</span>
        </header>
        {memory && memory.episodes.length > 0 ? (
          <ul className="episodes">
            {memory.episodes.map((e) => (
              <li key={e.id} className="episode">
                <div className="episode__head">
                  <span className="mono">{e.id}</span>
                  <span className={`badge badge--${e.outcome === 'MITIGATED' ? 'mitigated' : e.outcome === 'ERROR' ? 'open' : 'neutral'}`}>{e.outcome.toLowerCase() || 'unknown'}</span>
                </div>
                <div className="small">
                  {e.incident_id}
                  {e.cve_id ? <span className="mono muted"> {e.cve_id}</span> : null}
                  <span className="muted"> {e.mode} mode, {e.tool_call_count} tool calls</span>
                </div>
                {e.summary ? <div className="small muted">{e.summary}</div> : null}
                <div className="small muted">{formatEpoch(e.started_at)}</div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="empty">No episodes recorded. Each agent run is stored with its tool calls.</p>
        )}
      </section>

      <section className="section">
        <header className="section__head">
          <h2 className="section__title">Simulations</h2>
          <span className="section__hint">{memory?.simulations.length ?? 0}</span>
        </header>
        {memory && memory.simulations.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>Simulation</th>
                <th>Bridge / role</th>
                <th className="num">Exposure</th>
                <th className="num">Safe</th>
              </tr>
            </thead>
            <tbody>
              {memory.simulations.map((s) => (
                <tr key={s.id}>
                  <td>
                    <span className="mono small">{s.id}</span>
                    <div className="small muted">
                      {s.incident_id} {formatEpoch(s.timestamp)}
                    </div>
                  </td>
                  <td className="small">
                    {s.bridge_service}
                    <div className="muted">{s.iam_role}</div>
                  </td>
                  <td className="num mono">
                    {s.exposure_before} → {s.exposure_after}
                  </td>
                  <td className="num">{s.safe ? <span className="ok">yes</span> : <span className="bad">no</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="empty">No simulations yet. simulate_remediation records each sandbox rehearsal here.</p>
        )}
      </section>
    </>
  );
}
