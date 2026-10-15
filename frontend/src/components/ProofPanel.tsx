import type { MemoryOverview } from '../api';
import type { RunState } from '../runState';
import { isRunActive } from '../runState';
import type { RollbackOutcome } from './DecisionCard';
import DecisionCard from './DecisionCard';
import MemoryPanel from './MemoryPanel';

export type ProofTab = 'proof' | 'memory';

interface Props {
  run: RunState;
  tab: ProofTab;
  onTabChange: (tab: ProofTab) => void;
  memory: MemoryOverview | null;
  memoryLoading: boolean;
  memoryError: string | null;
  onRefreshMemory: () => void;
  rollback: RollbackOutcome | null;
  rollbackBusy: boolean;
  onRollback: (auditId: string) => void;
  onViewSandbox: (name: string) => void;
  viewingSandbox: boolean;
}

export default function ProofPanel({
  run,
  tab,
  onTabChange,
  memory,
  memoryLoading,
  memoryError,
  onRefreshMemory,
  rollback,
  rollbackBusy,
  onRollback,
  onViewSandbox,
  viewingSandbox,
}: Props) {
  const active = isRunActive(run);
  const hasStream = run.thinking.length > 0 || run.narrative.length > 0;

  return (
    <>
      <div className="tabs" role="tablist">
        <button type="button" role="tab" aria-selected={tab === 'proof'} className={`tab ${tab === 'proof' ? 'is-active' : ''}`} onClick={() => onTabChange('proof')}>
          Decision proof
        </button>
        <button type="button" role="tab" aria-selected={tab === 'memory'} className={`tab ${tab === 'memory' ? 'is-active' : ''}`} onClick={() => onTabChange('memory')}>
          Memory
          {memory ? <span className="tab__count">{memory.episodes.length + memory.playbooks.length}</span> : null}
        </button>
      </div>

      {tab === 'memory' ? (
        <MemoryPanel memory={memory} loading={memoryLoading} error={memoryError} onRefresh={onRefreshMemory} />
      ) : (
        <>
          {run.started ? (
            <section className="section section--tight">
              <div className="runmeta">
                <span>
                  run <span className="mono">{run.runId ?? run.started.run_id}</span>
                </span>
                <span>
                  {run.started.mode} mode{run.started.model ? ` (${run.started.model})` : ''}
                </span>
                <span>{run.started.tools.length} MCP tools</span>
                <span>{run.eventCount} events</span>
              </div>
            </section>
          ) : null}

          {run.errors.length > 0 ? (
            <section className="section section--tight">
              {run.errors.map((e, i) => (
                <p key={i} className="inline-error">
                  {e.recoverable ? 'Recovered: ' : 'Run stopped: '}
                  {e.message}
                </p>
              ))}
            </section>
          ) : null}

          <section className="section">
            <header className="section__head">
              <h2 className="section__title">Narrative</h2>
              <span className="section__hint">{active ? 'streaming' : ''}</span>
            </header>
            {run.thinking ? (
              <details className="thinking" open>
                <summary>Model reasoning</summary>
                <p className="thinking__text">{run.thinking}</p>
              </details>
            ) : null}
            {run.narrative ? (
              <p className="narrative">
                {run.narrative}
                {active ? <span className="caret" aria-hidden="true" /> : null}
              </p>
            ) : null}
            {!hasStream && (run.completed || run.decision) ? (
              <>
                <p className="narrative">{run.completed?.summary ?? run.decision?.justification}</p>
                <p className="muted small">
                  {run.started?.mode === 'deterministic'
                    ? 'Deterministic mode: this explanation is assembled from the graph evidence, without an LLM.'
                    : 'Assembled from the graph evidence.'}
                </p>
              </>
            ) : null}
            {!hasStream && !run.completed && !run.decision ? (
              <p className="empty">
                {active
                  ? 'The agent is working. Its reasoning and the final explanation appear here as they stream.'
                  : 'The agent explains its decision here in plain language, citing the graph scores it relied on.'}
              </p>
            ) : null}
          </section>

          <DecisionCard run={run} rollback={rollback} rollbackBusy={rollbackBusy} onRollback={onRollback} onViewSandbox={onViewSandbox} viewingSandbox={viewingSandbox} />
        </>
      )}
    </>
  );
}
