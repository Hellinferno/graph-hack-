/**
 * In-browser stand-in for the backend, enabled with `?mock=1`.
 *
 * It replays `/mock-fixture.json`, a recording of a real AegisGraph session captured from the live API by
 * `scripts/record_mock_fixture.py`. Every payload goes through the same normalisers as the HTTP client, so the
 * preview shows exactly what the real system produced. The recording covers three phases:
 * `before` (seeded), `after` (remediated) and `restored` (rolled back).
 */
import type { AegisClient, RunRecord, StartRunRequest } from '../api';
import { ApiError, normalizers } from '../api';
import type { AgentEvent, GraphSnapshot, JsonObject, JsonValue } from '../events';
import { parseAgentEvent } from '../events';
import type { GetDecisionProofResult, RollbackRemediationResult } from '../tools';

interface PhaseRecording {
  health: JsonValue;
  incidents: JsonValue;
  graph: JsonValue;
  graphs: JsonValue;
  memory: JsonValue;
  proof: JsonValue;
}

interface Fixture {
  recorded_at: number;
  seed: JsonValue;
  tools: JsonValue;
  before: PhaseRecording;
  after: PhaseRecording;
  restored: PhaseRecording;
  sandbox_graph: string;
  sandbox: JsonValue;
  run: { run_id: string; mode: string; events: JsonObject[] };
  audit_id: string;
  rollback: JsonValue;
}

type Phase = 'before' | 'after' | 'restored';

/** Replay pacing: the real run takes well under a second, so stretch it to something watchable. */
const REPLAY_SPEEDUP = 14;
const MIN_STEP_MS = 90;
const MAX_STEP_MS = 900;
const SLOW_EVENTS = new Set(['stage', 'decision', 'graph_highlight']);

const wait = (ms: number) => new Promise<void>((resolve) => window.setTimeout(resolve, ms));

let fixturePromise: Promise<Fixture> | null = null;

function loadFixture(): Promise<Fixture> {
  fixturePromise ??= fetch(`${import.meta.env.BASE_URL}mock-fixture.json`).then((response) => {
    if (!response.ok) throw new ApiError(response.status, `mock fixture missing (HTTP ${response.status})`);
    return response.json() as Promise<Fixture>;
  });
  return fixturePromise;
}

function replayDelays(events: JsonObject[]): number[] {
  return events.map((event, i) => {
    if (i === 0) return 250;
    const gap = (Number(event.ts) - Number(events[i - 1].ts)) * 1000 * REPLAY_SPEEDUP;
    const base = Math.min(MAX_STEP_MS, Math.max(MIN_STEP_MS, Number.isFinite(gap) ? gap : MIN_STEP_MS));
    return SLOW_EVENTS.has(String(event.type)) ? base + 260 : base;
  });
}

export function createMockClient(): AegisClient {
  let phase: Phase = 'before';
  let hasRun = false;
  let runCounter = 0;
  const runs = new Map<string, { request: StartRunRequest; events: AgentEvent[]; status: RunRecord['status'] }>();

  const current = async (): Promise<PhaseRecording> => {
    const fixture = await loadFixture();
    return fixture[phase];
  };
  /** Memory is never rolled back: once a run has finished, the episode stays. */
  const memoryRecording = async (): Promise<JsonValue> => {
    const fixture = await loadFixture();
    return hasRun ? fixture[phase === 'before' ? 'after' : phase].memory : fixture.before.memory;
  };

  const eventsFor = (fixture: Fixture, runId: string): AgentEvent[] =>
    fixture.run.events
      .map((e) => parseAgentEvent('', JSON.stringify({ ...e, run_id: runId })))
      .filter((e): e is AgentEvent => e !== null);

  return {
    async health() {
      await wait(80);
      return normalizers.health((await current()).health);
    },
    async seed() {
      await wait(300);
      const fixture = await loadFixture();
      phase = 'before';
      return normalizers.seed(fixture.seed);
    },
    async incidents() {
      await wait(60);
      return normalizers.incidents((await current()).incidents);
    },
    async incident(id) {
      await wait(60);
      const proof = (await current()).proof as unknown as GetDecisionProofResult;
      if (proof?.incident && (proof.incident as JsonObject).id === id) return proof;
      throw new ApiError(404, `Mock mode only recorded the decision proof of the demo incident (${id} requested)`);
    },
    async graph() {
      await wait(100);
      return normalizers.snapshot((await current()).graph, 'aegis_prod_graph');
    },
    async graphs() {
      await wait(60);
      return normalizers.graphOverview((await current()).graphs);
    },
    async graphByName(name) {
      await wait(100);
      const fixture = await loadFixture();
      if (name === fixture.sandbox_graph) return normalizers.snapshot(fixture.sandbox, name);
      const prod: GraphSnapshot = normalizers.snapshot((await current()).graph, 'aegis_prod_graph');
      if (name === prod.graph) return prod;
      throw new ApiError(404, `Graph ${name} was not recorded in mock mode`);
    },
    async tools() {
      await wait(40);
      return normalizers.tools((await loadFixture()).tools);
    },
    async callTool(name) {
      await wait(60);
      throw new ApiError(400, `Mock mode replays a recorded session and cannot call ${name} directly`);
    },
    async startRun(body) {
      await wait(150);
      const fixture = await loadFixture();
      runCounter += 1;
      const runId = `mock-${fixture.run.run_id}-${runCounter}`;
      runs.set(runId, { request: body, events: eventsFor(fixture, runId), status: 'running' });
      return { run_id: runId };
    },
    async run(runId) {
      await wait(40);
      const run = runs.get(runId);
      if (!run) throw new ApiError(404, `Run ${runId} not found`);
      return { run_id: runId, status: run.status, events: run.events };
    },
    subscribeRunEvents(runId, handlers) {
      const run = runs.get(runId);
      let cancelled = false;
      let timer: number | undefined;
      if (!run) {
        window.setTimeout(() => handlers.onError(new ApiError(404, `Run ${runId} not found`)), 0);
        return () => undefined;
      }
      void loadFixture().then((fixture) => {
        const delays = replayDelays(fixture.run.events);
        let index = 0;
        const step = () => {
          if (cancelled) return;
          if (index >= run.events.length) {
            run.status = 'completed';
            hasRun = true;
            handlers.onDone();
            return;
          }
          const event = run.events[index];
          const delay = delays[index] ?? MIN_STEP_MS;
          index += 1;
          timer = window.setTimeout(() => {
            if (cancelled) return;
            if (event.type === 'tool_result' && event.name === 'execute_remediation' && !event.is_error) phase = 'after';
            if (event.type === 'run_completed') hasRun = true;
            handlers.onEvent(event);
            step();
          }, delay);
        };
        step();
      });
      return () => {
        cancelled = true;
        if (timer !== undefined) window.clearTimeout(timer);
      };
    },
    async memory() {
      await wait(60);
      return normalizers.memory(await memoryRecording());
    },
    async rollback(auditId) {
      await wait(350);
      const fixture = await loadFixture();
      if (phase !== 'after') throw new ApiError(400, `Audit ${auditId} has nothing to roll back`);
      phase = 'restored';
      return fixture.rollback as unknown as RollbackRemediationResult;
    },
  };
}
