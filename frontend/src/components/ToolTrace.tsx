import { useState } from 'react';
import type { JsonObject } from '../events';
import { asNumber, asObject, asObjectArray, asString, formatMs } from '../lib/json';
import type { RunPhase, ToolTraceRow } from '../runState';
import type { CypherTrace } from '../tools';
import { toolErrorMessage } from '../tools';
import JsonBlock from './JsonBlock';

interface Props {
  rows: ToolTraceRow[];
  phase: RunPhase;
}

function cypherTraces(result: JsonObject | null): CypherTrace[] {
  if (!result) return [];
  return asObjectArray(result.cypher).map((t) => ({
    graph: asString(t.graph),
    cypher: asString(t.cypher),
    params: asObject(t.params),
    run_time_ms: asNumber(t.run_time_ms),
    rows: asNumber(t.rows),
  }));
}

function TraceRow({ row }: { row: ToolTraceRow }) {
  const [open, setOpen] = useState(false);
  const traces = cypherTraces(row.result);
  const error = toolErrorMessage(row.result);
  const state = row.pending ? 'pending' : row.is_error || error ? 'error' : 'ok';
  const argEntries = Object.entries(row.args);

  return (
    <li className={`trace trace--${state}`}>
      <button type="button" className="trace__head" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        <span className="trace__seq">{row.seq}</span>
        <span className="trace__name mono">{row.name}</span>
        <span className="trace__meta">
          {row.pending ? 'running' : formatMs(row.duration_ms)}
          {traces.length > 0 ? ` · ${traces.length} ${traces.length === 1 ? 'query' : 'queries'}` : ''}
        </span>
        <span className="trace__chevron" aria-hidden="true">
          {open ? '▾' : '▸'}
        </span>
      </button>
      {!open && argEntries.length > 0 ? (
        <div className="trace__args-preview mono">
          {argEntries
            .slice(0, 3)
            .map(([k, v]) => `${k}=${typeof v === 'string' ? (v.length > 40 ? `${v.slice(0, 40)}…` : v) : JSON.stringify(v)}`)
            .join('  ')}
        </div>
      ) : null}
      {open ? (
        <div className="trace__body">
          <div className="trace__block">
            <div className="trace__label">Arguments</div>
            <JsonBlock value={row.args} maxHeight={160} />
          </div>
          <div className="trace__block">
            <div className="trace__label">{row.pending ? 'Result (waiting)' : error ? 'Error' : 'Result'}</div>
            {row.pending ? <p className="empty">Waiting for the MCP server…</p> : error ? <p className="inline-error">{error}</p> : <JsonBlock value={row.result} />}
          </div>
          {traces.length > 0 ? (
            <div className="trace__block">
              <div className="trace__label">Cypher executed</div>
              <ol className="cypher-list">
                {traces.map((t, i) => (
                  <li key={i} className="cypher">
                    <div className="cypher__meta">
                      <span className="mono">{t.graph || 'graph'}</span>
                      <span>
                        {t.rows} row{t.rows === 1 ? '' : 's'}
                      </span>
                      <span>{formatMs(t.run_time_ms)}</span>
                    </div>
                    <pre className="cypher__text">{t.cypher}</pre>
                    {Object.keys(t.params).length > 0 ? <pre className="cypher__params">params {JSON.stringify(t.params)}</pre> : null}
                  </li>
                ))}
              </ol>
            </div>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}

export default function ToolTrace({ rows, phase }: Props) {
  return (
    <section className="section section--grow">
      <header className="section__head">
        <h2 className="section__title">MCP tool trace</h2>
        <span className="section__hint">{rows.length > 0 ? `${rows.length} call${rows.length === 1 ? '' : 's'}` : ''}</span>
      </header>
      {rows.length === 0 ? (
        <p className="empty">
          {phase === 'idle'
            ? 'Every graph query the agent makes will appear here with its arguments, result and the exact Cypher executed.'
            : 'Waiting for the first tool call…'}
        </p>
      ) : (
        <ol className="trace-list">
          {rows.map((row) => (
            <TraceRow key={`${row.call_id}-${row.seq}`} row={row} />
          ))}
        </ol>
      )}
    </section>
  );
}
