import type { IncidentSummary, ToolInfo } from '../api';
import { modeHint } from '../api';
import type { RunMode } from '../events';
import { formatEpoch } from '../lib/json';

interface Props {
  incidents: IncidentSummary[];
  loading: boolean;
  error: string | null;
  selectedId: string | null;
  onSelect: (id: string) => void;
  mode: RunMode;
  onModeChange: (mode: RunMode) => void;
  llmConfigured: boolean;
  alertText: string;
  onAlertChange: (text: string) => void;
  onStart: () => void;
  running: boolean;
  startBlockedReason: string | null;
  tools: ToolInfo[];
}

const MODES: { value: RunMode; label: string }[] = [
  { value: 'auto', label: 'Auto' },
  { value: 'deterministic', label: 'Deterministic' },
  { value: 'llm', label: 'LLM' },
];

export default function IncidentPanel({
  incidents,
  loading,
  error,
  selectedId,
  onSelect,
  mode,
  onModeChange,
  llmConfigured,
  alertText,
  onAlertChange,
  onStart,
  running,
  startBlockedReason,
  tools,
}: Props) {
  const hint = modeHint(mode, llmConfigured);
  const servers = Array.from(new Set(tools.map((t) => t.server))).filter(Boolean);

  return (
    <>
      <section className="section">
        <header className="section__head">
          <h2 className="section__title">Incidents</h2>
          <span className="section__hint">{incidents.length > 0 ? `${incidents.length} in the graph` : loading ? 'loading' : ''}</span>
        </header>
        {error ? <p className="inline-error">{error}</p> : null}
        {!error && !loading && incidents.length === 0 ? (
          <p className="empty">No incidents in the production graph. Reseed to load the demo dataset.</p>
        ) : null}
        <ul className="incident-list">
          {incidents.map((incident) => {
            const selected = incident.id === selectedId;
            const status = incident.status.toUpperCase();
            return (
              <li key={incident.id}>
                <button
                  type="button"
                  className={`incident ${selected ? 'is-selected' : ''}`}
                  onClick={() => onSelect(incident.id)}
                  aria-pressed={selected}
                >
                  <span className="incident__row">
                    <span className="incident__id">{incident.id}</span>
                    <span className={`badge badge--${status === 'OPEN' ? 'open' : status === 'MITIGATED' ? 'mitigated' : 'neutral'}`}>
                      {status.toLowerCase()}
                    </span>
                  </span>
                  <span className="incident__title">{incident.title || 'Untitled incident'}</span>
                  <span className="incident__meta">
                    {incident.cve_id ? <span className="mono">{incident.cve_id}</span> : null}
                    <span>{formatEpoch(incident.timestamp)}</span>
                    {incident.audit_count > 0 ? (
                      <span>
                        {incident.audit_count} audit{incident.audit_count === 1 ? '' : 's'}
                      </span>
                    ) : null}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </section>

      <section className="section">
        <header className="section__head">
          <h2 className="section__title">Run the agent</h2>
        </header>

        <div className="field">
          <span className="field__label">Mode</span>
          <div className="segmented" role="group" aria-label="Agent mode">
            {MODES.map((m) => {
              const disabled = m.value === 'llm' && !llmConfigured;
              return (
                <button
                  key={m.value}
                  type="button"
                  className={`segmented__item ${mode === m.value ? 'is-active' : ''}`}
                  onClick={() => onModeChange(m.value)}
                  disabled={disabled || running}
                  aria-pressed={mode === m.value}
                  title={disabled ? 'LLM mode needs OPENROUTER_API_KEY or ANTHROPIC_API_KEY in the project .env (restart the API)' : undefined}
                >
                  {m.label}
                </button>
              );
            })}
          </div>
          {hint ? <span className="field__hint">{hint}</span> : null}
        </div>

        <label className="field">
          <span className="field__label">Alert text</span>
          <textarea
            className="textarea"
            value={alertText}
            onChange={(e) => onAlertChange(e.target.value)}
            rows={5}
            placeholder="Paste the alert that paged you. The selected incident's raw alert is filled in by default."
            disabled={running}
            spellCheck={false}
          />
        </label>

        <button type="button" className="btn btn--primary btn--block" onClick={onStart} disabled={running || !!startBlockedReason}>
          {running ? 'Investigating…' : 'Investigate & remediate'}
        </button>
        {startBlockedReason && !running ? <p className="field__hint">{startBlockedReason}</p> : null}

        {tools.length > 0 ? (
          <details className="tools">
            <summary>
              {tools.length} MCP tool{tools.length === 1 ? '' : 's'} registered{servers.length > 0 ? ` (${servers.join(', ')})` : ''}
            </summary>
            <ul className="tools__list">
              {tools.map((t) => (
                <li key={`${t.server}:${t.name}`}>
                  <span className="mono">{t.name}</span>
                  {t.description ? <span className="tools__desc">{t.description}</span> : null}
                </li>
              ))}
            </ul>
          </details>
        ) : null}
      </section>
    </>
  );
}
