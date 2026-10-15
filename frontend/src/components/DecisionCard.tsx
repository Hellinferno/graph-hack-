import { useMemo } from 'react';
import type { CodeOwner } from '../events';
import { formatMs, formatScore } from '../lib/json';
import type { RunPhase, RunState } from '../runState';
import { latestResult } from '../runState';
import type {
  ExecuteRemediationResult,
  FindCodeOwnerResult,
  FindEntryPointsResult,
  RankServiceCriticalityResult,
  SimulateRemediationResult,
  TraceBlastRadiusResult,
} from '../tools';
import { readResult } from '../tools';

export interface RollbackOutcome {
  auditId: string;
  status: 'ok' | 'error';
  message: string;
}

interface Props {
  run: RunState;
  rollback: RollbackOutcome | null;
  rollbackBusy: boolean;
  onRollback: (auditId: string) => void;
  onViewSandbox: (name: string) => void;
  viewingSandbox: boolean;
}

interface CentralityMerged {
  service: string;
  tier: string;
  rps: number;
  betweenness: number | null;
  pagerank: number | null;
}

function Flag({ ok, children }: { ok: boolean; children: string }) {
  return <span className={`flag ${ok ? 'flag--ok' : 'flag--bad'}`}>{children}</span>;
}

function EmptyState({ phase }: { phase: RunPhase }) {
  return (
    <section className="section">
      <h2 className="section__title">Decision proof</h2>
      <p className="empty">
        {phase === 'idle'
          ? 'Select an incident and start a run. The chosen bridge, its centrality scores, the sandbox rehearsal and the audit record will build up here as evidence arrives.'
          : 'Waiting for the first tool results…'}
      </p>
    </section>
  );
}

export default function DecisionCard({ run, rollback, rollbackBusy, onRollback, onViewSandbox, viewingSandbox }: Props) {
  const entry = latestResult<FindEntryPointsResult>(run, 'find_entry_points');
  const blastRows = run.trace.filter((r) => r.name === 'trace_blast_radius' && r.result && !r.is_error);
  const blast = blastRows.length > 0 ? readResult<TraceBlastRadiusResult>(blastRows[0].result) : null;
  const verifyBlast = blastRows.length > 1 ? readResult<TraceBlastRadiusResult>(blastRows[blastRows.length - 1].result) : null;
  const rank = latestResult<RankServiceCriticalityResult>(run, 'rank_service_criticality');
  const sim = latestResult<SimulateRemediationResult>(run, 'simulate_remediation');
  const exec = latestResult<ExecuteRemediationResult>(run, 'execute_remediation');
  const ownerResult = latestResult<FindCodeOwnerResult>(run, 'find_code_owner');
  const decision = run.decision;

  const bridge = decision?.bridge_service ?? exec?.isolated_bridge ?? null;
  const role = decision?.iam_role ?? exec?.quarantined_role ?? null;
  const decisionOwner: CodeOwner | null = decision && typeof decision.code_owner === 'object' ? decision.code_owner : null;
  const owner: CodeOwner | null = exec?.assigned_code_owner ?? decisionOwner ?? ownerResult?.recommended ?? null;
  const ownerHandle = owner?.handle ?? (typeof decision?.code_owner === 'string' ? decision.code_owner : null);
  const auditId = exec?.audit_id ?? run.completed?.audit_id ?? null;
  const rolledBack = rollback?.status === 'ok' && rollback.auditId === auditId;
  const scores = decision?.scores ?? exec?.scores ?? null;
  const bestMatch = entry?.matches.find((m) => m.cve_id === entry.best_cve_id) ?? entry?.matches[0] ?? null;

  const centrality = useMemo<CentralityMerged[]>(() => {
    if (!rank) return [];
    const map = new Map<string, CentralityMerged>();
    for (const row of rank.betweenness ?? []) {
      map.set(row.service, { service: row.service, tier: row.tier, rps: row.rps, betweenness: row.score, pagerank: null });
    }
    for (const row of rank.pagerank ?? []) {
      const existing = map.get(row.service);
      if (existing) existing.pagerank = row.score;
      else map.set(row.service, { service: row.service, tier: row.tier, rps: row.rps, betweenness: null, pagerank: row.score });
    }
    return [...map.values()].sort((a, b) => (b.betweenness ?? 0) - (a.betweenness ?? 0) || (b.pagerank ?? 0) - (a.pagerank ?? 0));
  }, [rank]);

  if (!entry && !blast && !rank && !sim && !exec && !decision && !run.completed) return <EmptyState phase={run.phase} />;

  return (
    <>
      {bestMatch ? (
        <section className="section">
          <header className="section__head">
            <h2 className="section__title">Anchor</h2>
            <span className="section__hint">hybrid vector + full-text match</span>
          </header>
          <div className="kv">
            <div className="kv__row">
              <span className="kv__key">Vulnerability</span>
              <span className="kv__val">
                <span className="mono">{bestMatch.cve_id}</span> {bestMatch.severity} {formatScore(bestMatch.cvss, 1)}
              </span>
            </div>
            <div className="kv__row">
              <span className="kv__key">Package</span>
              <span className="kv__val">
                {bestMatch.affected_packages.map((p) => `${p.name} ${p.version} → ${p.fixed_version}`).join(', ') || '—'}
              </span>
            </div>
            <div className="kv__row">
              <span className="kv__key">Entry services</span>
              <span className="kv__val">{bestMatch.entry_services.join(', ') || '—'}</span>
            </div>
            <div className="kv__row">
              <span className="kv__key">Score</span>
              <span className="kv__val mono">
                {formatScore(bestMatch.combined_score, 3)} (vector {formatScore(bestMatch.vector_distance, 3)}, text {formatScore(bestMatch.fulltext_score, 2)})
              </span>
            </div>
          </div>
          {entry && entry.matches.length > 1 ? (
            <p className="muted small">
              Also considered: {entry.matches.filter((m) => m.cve_id !== bestMatch.cve_id).map((m) => `${m.cve_id} (${formatScore(m.combined_score, 2)})`).join(', ')}
            </p>
          ) : null}
        </section>
      ) : null}

      {blast ? (
        <section className="section">
          <header className="section__head">
            <h2 className="section__title">Exposure paths</h2>
            <span className="section__hint">
              {blast.total_paths} active path{blast.total_paths === 1 ? '' : 's'} into {blast.exposed_databases.length} PII database
              {blast.exposed_databases.length === 1 ? '' : 's'}
            </span>
          </header>
          {blast.exposed_paths.length === 0 ? (
            <p className="empty">No active path reaches a PII database.</p>
          ) : (
            <>
              {bridge ? (
                <p className="small">
                  <span className="paths__bridge">{bridge}</span> lies on{' '}
                  <b>
                    {blast.exposed_paths.filter((p) => p.path_nodes.includes(bridge)).length} of {blast.total_paths}
                  </b>{' '}
                  paths from {blast.origin_services.join(', ') || 'the origin'}.
                </p>
              ) : null}
              <ol className="paths">
                {blast.exposed_paths.map((p, i) => (
                  <li key={i} className="paths__row">
                    <div className="paths__chain mono small">
                      {p.path_nodes.map((n, j) => (
                        <span key={j}>
                          {j > 0 ? <span className="paths__arrow"> → </span> : null}
                          <span className={n === bridge ? 'paths__bridge' : n === p.database ? 'paths__db' : n === p.iam_role ? 'paths__role' : ''}>{n}</span>
                        </span>
                      ))}
                    </div>
                    <div className="paths__meta small muted">
                      {p.total_hops} hops · {p.classification} · {p.access_mode} via {p.iam_role}
                      {p.pivot_tier === 'critical' ? ' · critical-tier pivot' : ''}
                    </div>
                  </li>
                ))}
              </ol>
            </>
          )}
        </section>
      ) : null}

      {decision || bridge ? (
        <section className="section decision">
          <header className="section__head">
            <h2 className="section__title">Decision</h2>
            {decision ? (
              <span className="section__hint">
                {decision.sim_passed === null ? 'no simulation (no eligible target)' : decision.sim_passed ? 'simulation passed' : 'simulation did not pass'}
              </span>
            ) : null}
          </header>
          <div className="decision__grid">
            <div>
              <div className="decision__label">Bridge to isolate</div>
              <div className="decision__value">{bridge ?? '—'}</div>
            </div>
            <div>
              <div className="decision__label">Role to quarantine</div>
              <div className="decision__value">{role ?? '—'}</div>
            </div>
            <div>
              <div className="decision__label">Betweenness</div>
              <div className="decision__value mono">{formatScore(scores?.betweenness)}</div>
            </div>
            <div>
              <div className="decision__label">PageRank</div>
              <div className="decision__value mono">{formatScore(scores?.pagerank)}</div>
            </div>
          </div>
          {decision?.action ? (
            <div className="kv__row">
              <span className="kv__key">Action</span>
              <span className="kv__val mono">{decision.action}</span>
            </div>
          ) : null}
          {decision?.justification ? <p className="decision__why">{decision.justification}</p> : null}
        </section>
      ) : null}

      {decision?.candidates && decision.candidates.length > 0 ? (
        <section className="section">
          <header className="section__head">
            <h2 className="section__title">Candidate chokepoints</h2>
            <span className="section__hint">pivot services on the exposure paths</span>
          </header>
          <table className="table">
            <thead>
              <tr>
                <th>Service</th>
                <th>Tier</th>
                <th className="num">Paths</th>
                <th className="num">Betweenness</th>
                <th className="num">PageRank</th>
                <th>Verdict</th>
              </tr>
            </thead>
            <tbody>
              {decision.candidates.map((c) => (
                <tr key={c.service} className={c.service === bridge ? 'is-bridge' : ''} title={c.reason || undefined}>
                  <td>{c.service}</td>
                  <td className={c.tier === 'critical' ? 'tier-critical' : 'muted'}>{c.tier}</td>
                  <td className="num mono">
                    {c.coverage}/{c.total_paths}
                  </td>
                  <td className="num mono">{formatScore(c.betweenness, 2)}</td>
                  <td className="num mono">{formatScore(c.pagerank, 3)}</td>
                  <td>
                    {c.service === bridge ? <span className="ok">chosen</span> : c.eligible ? <span className="muted">eligible</span> : <span className="bad">protected</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted small">Ranked by attack paths covered, then betweenness, then lowest traffic. Critical-tier services are never isolated.</p>
        </section>
      ) : null}

      {centrality.length > 0 ? (
        <section className="section">
          <header className="section__head">
            <h2 className="section__title">Service centrality</h2>
            <span className="section__hint">algo.betweenness and algo.pageRank over ROUTES_TO</span>
          </header>
          <table className="table">
            <thead>
              <tr>
                <th>Service</th>
                <th>Tier</th>
                <th className="num">rps</th>
                <th className="num">Betweenness</th>
                <th className="num">PageRank</th>
              </tr>
            </thead>
            <tbody>
              {centrality.map((row) => (
                <tr key={row.service} className={row.service === bridge ? 'is-bridge' : ''}>
                  <td>{row.service}</td>
                  <td className={row.tier === 'critical' ? 'tier-critical' : 'muted'}>{row.tier}</td>
                  <td className="num mono">{row.rps}</td>
                  <td className="num mono">{formatScore(row.betweenness, 3)}</td>
                  <td className="num mono">{formatScore(row.pagerank, 4)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted small">
            Betweenness counts the shortest service-to-service paths that run through a service, so a high score marks a
            chokepoint. PageRank measures how much of the mesh depends on a service.
          </p>
        </section>
      ) : null}

      {sim ? (
        <section className="section">
          <header className="section__head">
            <h2 className="section__title">Sandbox rehearsal</h2>
            <span className="section__hint mono">{sim.sandbox_graph}</span>
          </header>
          <div className="exposure">
            <div className="exposure__num">
              <span className="exposure__value">{sim.exposure_before}</span>
              <span className="exposure__label">exposure paths before</span>
            </div>
            <span className="exposure__arrow" aria-hidden="true">
              →
            </span>
            <div className="exposure__num">
              <span className={`exposure__value ${sim.exposure_after === 0 ? 'is-zero' : 'is-nonzero'}`}>{sim.exposure_after}</span>
              <span className="exposure__label">after severing</span>
            </div>
            <div className={`verdict ${sim.safe_to_execute ? 'verdict--ok' : 'verdict--bad'}`}>
              {sim.safe_to_execute ? 'Safe to execute' : 'Not safe to execute'}
            </div>
          </div>
          <div className="flags">
            <Flag ok={sim.exposure_closed}>exposure closed</Flag>
            <Flag ok={sim.critical_flows_intact}>critical flows intact</Flag>
            <Flag ok={sim.critical_services_connected}>critical tier connected</Flag>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Critical flow</th>
                <th className="num">Status</th>
              </tr>
            </thead>
            <tbody>
              {sim.critical_flows.map((f) => (
                <tr key={`${f.source}-${f.target}`}>
                  <td>
                    {f.source} → {f.target}
                  </td>
                  <td className="num">{f.intact ? <span className="ok">intact</span> : <span className="bad">broken</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="components">
            <div className="kv__key">Connected components after severing (algo.WCC)</div>
            {sim.wcc_components.map((c) => (
              <div key={String(c.component_id)} className="component">
                <span className="component__id mono">#{String(c.component_id)}</span>
                <span className="component__services">{c.services.join(', ')}</span>
              </div>
            ))}
          </div>
          <div className="kv small muted">
            <div className="kv__row">
              <span className="kv__key">Severed routes</span>
              <span className="kv__val">{sim.severed_routes.map((r) => `${r.src} → ${r.dst}`).join(', ') || '—'}</span>
            </div>
            <div className="kv__row">
              <span className="kv__key">Quarantined access</span>
              <span className="kv__val">{sim.quarantined_access.map((a) => `${a.role} → ${a.database}`).join(', ') || '—'}</span>
            </div>
          </div>
          <div className="actions">
            <button
              type="button"
              className="btn btn--small"
              onClick={() => onViewSandbox(sim.sandbox_graph)}
              disabled={!sim.sandbox_kept || viewingSandbox}
              title={sim.sandbox_kept ? undefined : 'The sandbox was deleted after the simulation (AEGIS_KEEP_SANDBOX=false)'}
            >
              {viewingSandbox ? 'Viewing sandbox graph' : 'View sandbox graph'}
            </button>
            {!sim.sandbox_kept ? <span className="muted small">sandbox not kept</span> : null}
          </div>
        </section>
      ) : null}

      {exec ? (
        <section className="section">
          <header className="section__head">
            <h2 className="section__title">Action taken</h2>
            <span className={`section__hint ${exec.status === 'ACTION_EXECUTED' ? 'ok' : 'bad'}`}>{exec.status.toLowerCase().replaceAll('_', ' ')}</span>
          </header>
          {exec.status !== 'ACTION_EXECUTED' ? <p className="inline-error">{exec.reason ?? 'The guarded action was refused.'}</p> : null}
          <div className="kv">
            {auditId ? (
              <div className="kv__row">
                <span className="kv__key">Audit</span>
                <span className="kv__val mono">{auditId}</span>
              </div>
            ) : null}
            {exec.incident_status ? (
              <div className="kv__row">
                <span className="kv__key">Incident</span>
                <span className="kv__val">{rolledBack ? 'OPEN (rolled back)' : exec.incident_status}</span>
              </div>
            ) : null}
            {exec.verification ? (
              <div className="kv__row">
                <span className="kv__key">Verification</span>
                <span className="kv__val">
                  exposure {exec.verification.exposed_paths_before} → <b>{exec.verification.exposed_paths_after}</b>
                  {verifyBlast ? ` (re-traced: ${verifyBlast.total_paths})` : ''}
                </span>
              </div>
            ) : null}
            {exec.mutations && exec.mutations.length > 0 ? (
              <details className="mutations">
                <summary>
                  {exec.mutations.length} reversible mutation{exec.mutations.length === 1 ? '' : 's'}
                </summary>
                <ul className="mutations__list mono small">
                  {exec.mutations.map((m, i) => (
                    <li key={i}>
                      {m.kind === 'edge' ? `${m.src} -[${m.type}]-> ${m.dst}` : `(${m.label ?? m.type}: ${m.name})`} {m.property}: {String(m.previous)} → {String(m.new)}
                    </li>
                  ))}
                </ul>
              </details>
            ) : null}
          </div>
          <div className="actions">
            {auditId ? (
              <button type="button" className="btn btn--small btn--danger" onClick={() => onRollback(auditId)} disabled={rollbackBusy || rolledBack}>
                {rollbackBusy ? 'Rolling back…' : rolledBack ? 'Rolled back' : 'Roll back this action'}
              </button>
            ) : null}
            {rollback && rollback.auditId === auditId ? (
              <span className={`small ${rollback.status === 'ok' ? 'ok' : 'bad'}`}>{rollback.message}</span>
            ) : null}
          </div>
        </section>
      ) : null}

      {owner || ownerHandle || exec?.pr_draft ? (
        <section className="section">
          <header className="section__head">
            <h2 className="section__title">Code owner and PR draft</h2>
          </header>
          {owner ? (
            <div className="owner">
              <div className="owner__name">
                {owner.name} <span className="mono muted">{owner.handle}</span>
                {owner.on_call ? <span className="badge badge--oncall">on call</span> : null}
              </div>
              <div className="muted small">{owner.team}</div>
              {owner.target_file ? (
                <div className="small">
                  <span className="mono">{owner.repo_name ? `${owner.repo_name}/` : ''}{owner.target_file}</span>
                  {owner.function ? <span className="muted"> — {owner.function}</span> : null}
                </div>
              ) : null}
              {owner.package ? (
                <div className="small">
                  bump <span className="mono">{owner.package}</span> {owner.current_version} → {owner.fixed_version}
                  {owner.expertise_score !== undefined ? <span className="muted"> (expertise {formatScore(owner.expertise_score, 2)})</span> : null}
                </div>
              ) : null}
            </div>
          ) : ownerHandle ? (
            <div className="owner__name mono">{ownerHandle}</div>
          ) : null}
          {exec?.pr_draft ? (
            <div className="pr">
              <div className="pr__title">{exec.pr_draft.title}</div>
              <div className="kv small">
                <div className="kv__row">
                  <span className="kv__key">Branch</span>
                  <span className="kv__val mono">{exec.pr_draft.branch}</span>
                </div>
                <div className="kv__row">
                  <span className="kv__key">Assignee</span>
                  <span className="kv__val mono">{exec.pr_draft.assignee}</span>
                </div>
                <div className="kv__row">
                  <span className="kv__key">File</span>
                  <span className="kv__val mono">{exec.pr_draft.file}</span>
                </div>
                {exec.pr_url ? (
                  <div className="kv__row">
                    <span className="kv__key">Draft URL</span>
                    <span className="kv__val mono">{exec.pr_url}</span>
                  </div>
                ) : null}
              </div>
              <details>
                <summary>PR body</summary>
                <pre className="json">{exec.pr_draft.body}</pre>
              </details>
            </div>
          ) : null}
        </section>
      ) : null}

      {run.completed ? (
        <section className="section">
          <header className="section__head">
            <h2 className="section__title">Outcome</h2>
            <span className={`badge badge--${run.completed.outcome === 'MITIGATED' ? 'mitigated' : run.completed.outcome === 'ERROR' ? 'open' : 'neutral'}`}>
              {run.completed.outcome.toLowerCase()}
            </span>
          </header>
          <p>{run.completed.summary}</p>
          <div className="kv small muted">
            <div className="kv__row">
              <span className="kv__key">Duration</span>
              <span className="kv__val">{formatMs(run.completed.duration_ms)}</span>
            </div>
            <div className="kv__row">
              <span className="kv__key">Tool calls</span>
              <span className="kv__val">{run.completed.tool_call_count}</span>
            </div>
            {run.completed.episode_id ? (
              <div className="kv__row">
                <span className="kv__key">Episode</span>
                <span className="kv__val mono">{run.completed.episode_id}</span>
              </div>
            ) : null}
          </div>
        </section>
      ) : null}
    </>
  );
}
