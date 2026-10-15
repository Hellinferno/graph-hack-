import type { RunPhase, StageState } from '../runState';
import { STAGE_BLURBS, STAGE_LABELS } from '../runState';

interface Props {
  stages: StageState[];
  phase: RunPhase;
}

export default function Stepper({ stages, phase }: Props) {
  const idle = phase === 'idle';
  return (
    <section className="section">
      <header className="section__head">
        <h2 className="section__title">Investigation stages</h2>
        <span className="section__hint">
          {phase === 'running' ? 'live' : phase === 'completed' ? 'finished' : phase === 'error' ? 'stopped' : phase === 'starting' ? 'starting' : ''}
        </span>
      </header>
      <ol className="stepper">
        {stages.map((stage) => (
          <li key={stage.name} className={`step step--${idle ? 'pending' : stage.status}`}>
            <span className="step__marker" aria-hidden="true">
              {stage.status === 'completed' ? '✓' : stage.status === 'skipped' ? '–' : stage.stage}
            </span>
            <div className="step__body">
              <div className="step__label">
                {STAGE_LABELS[stage.name]}
                {stage.status === 'started' ? <span className="step__state">in progress</span> : null}
                {stage.status === 'skipped' ? <span className="step__state">skipped</span> : null}
              </div>
              <div className="step__detail">{stage.detail || STAGE_BLURBS[stage.name]}</div>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
