/**
 * Reducer that folds the §5 event stream into UI state for one agent run.
 */
import type {
  AgentEvent,
  DecisionEvent,
  GraphHighlightEvent,
  JsonObject,
  RunCompletedEvent,
  RunErrorEvent,
  RunStartedEvent,
  StageName,
} from './events';
import { STAGE_NAMES } from './events';
import type { ToolResultBase } from './tools';
import { readResult } from './tools';

export type StageUiStatus = 'pending' | 'started' | 'completed' | 'skipped';

export interface StageState {
  stage: number;
  name: StageName;
  status: StageUiStatus;
  detail: string;
}

export interface ToolTraceRow {
  call_id: string;
  name: string;
  args: JsonObject;
  seq: number;
  result: JsonObject | null;
  duration_ms: number | null;
  is_error: boolean;
  pending: boolean;
}

export type RunPhase = 'idle' | 'starting' | 'running' | 'completed' | 'error';

export interface RunState {
  runId: string | null;
  phase: RunPhase;
  started: RunStartedEvent | null;
  stages: StageState[];
  thinking: string;
  narrative: string;
  trace: ToolTraceRow[];
  highlights: GraphHighlightEvent[];
  decision: DecisionEvent | null;
  completed: RunCompletedEvent | null;
  errors: RunErrorEvent[];
  streamError: string | null;
  eventCount: number;
  /** Bumped after execute_remediation / rollback_remediation results so the graph is refetched. */
  graphVersion: number;
  /** Latest successful result per tool name. */
  results: Record<string, JsonObject>;
}

export const STAGE_LABELS: Record<StageName, string> = {
  anchor: 'Anchor',
  blast_radius: 'Blast radius',
  chokepoint: 'Chokepoint',
  simulate: 'Simulate',
  act: 'Act',
};

export const STAGE_BLURBS: Record<StageName, string> = {
  anchor: 'Match the alert to a CVE and its entry services',
  blast_radius: 'Trace active paths to PII data stores',
  chokepoint: 'Rank pivots by centrality, pick a non-critical bridge',
  simulate: 'Rehearse the fix in a sandbox copy of the graph',
  act: 'Flip edge statuses, record the audit, verify',
};

const GRAPH_MUTATING_TOOLS = new Set(['execute_remediation', 'rollback_remediation']);

function freshStages(): StageState[] {
  return STAGE_NAMES.map((name, index) => ({ stage: index + 1, name, status: 'pending', detail: '' }));
}

export function initialRunState(): RunState {
  return {
    runId: null,
    phase: 'idle',
    started: null,
    stages: freshStages(),
    thinking: '',
    narrative: '',
    trace: [],
    highlights: [],
    decision: null,
    completed: null,
    errors: [],
    streamError: null,
    eventCount: 0,
    graphVersion: 0,
    results: {},
  };
}

export type RunAction =
  | { type: 'starting' }
  | { type: 'start'; runId: string }
  | { type: 'event'; event: AgentEvent }
  | { type: 'stream_done' }
  | { type: 'stream_error'; message: string }
  | { type: 'rolled_back' }
  | { type: 'clear' };

function applyEvent(state: RunState, event: AgentEvent): RunState {
  const next: RunState = { ...state, eventCount: state.eventCount + 1 };
  switch (event.type) {
    case 'run_started':
      return { ...next, started: event, phase: 'running' };
    case 'stage':
      return {
        ...next,
        stages: state.stages.map((s) =>
          s.name === event.name ? { ...s, status: event.status, detail: event.detail || s.detail } : s,
        ),
      };
    case 'thinking':
      return { ...next, thinking: state.thinking + event.text };
    case 'assistant_text':
      return { ...next, narrative: state.narrative + event.text };
    case 'tool_call':
      return {
        ...next,
        trace: [
          ...state.trace,
          {
            call_id: event.call_id,
            name: event.name,
            args: event.args ?? {},
            seq: event.seq,
            result: null,
            duration_ms: null,
            is_error: false,
            pending: true,
          },
        ],
      };
    case 'tool_result': {
      let matched = false;
      const trace = state.trace.map((row) => {
        if (matched) return row;
        const byId = row.call_id && row.call_id === event.call_id;
        const byName = !row.call_id && row.pending && row.name === event.name;
        if (!byId && !byName) return row;
        matched = true;
        return { ...row, result: event.result, duration_ms: event.duration_ms, is_error: event.is_error, pending: false };
      });
      if (!matched) {
        trace.push({
          call_id: event.call_id,
          name: event.name,
          args: {},
          seq: trace.length + 1,
          result: event.result,
          duration_ms: event.duration_ms,
          is_error: event.is_error,
          pending: false,
        });
      }
      const results = event.is_error ? state.results : { ...state.results, [event.name]: event.result };
      const graphVersion = GRAPH_MUTATING_TOOLS.has(event.name) && !event.is_error ? state.graphVersion + 1 : state.graphVersion;
      return { ...next, trace, results, graphVersion };
    }
    case 'graph_highlight':
      return { ...next, highlights: [...state.highlights, event] };
    case 'decision':
      return { ...next, decision: event };
    case 'run_completed':
      return { ...next, completed: event, phase: 'completed' };
    case 'error':
      return { ...next, errors: [...state.errors, event], phase: event.recoverable ? state.phase : 'error' };
    default:
      return next;
  }
}

export function runReducer(state: RunState, action: RunAction): RunState {
  switch (action.type) {
    case 'starting':
      return { ...initialRunState(), phase: 'starting', graphVersion: state.graphVersion };
    case 'start':
      return { ...initialRunState(), runId: action.runId, phase: 'running', graphVersion: state.graphVersion };
    case 'event':
      return applyEvent(state, action.event);
    case 'stream_done':
      if (state.phase === 'completed' || state.phase === 'error') return state;
      return {
        ...state,
        phase: state.completed ? 'completed' : state.errors.length > 0 ? 'error' : 'completed',
        streamError: state.completed ? state.streamError : (state.streamError ?? 'Stream ended before run_completed'),
      };
    case 'stream_error':
      return { ...state, streamError: action.message, phase: state.phase === 'completed' ? 'completed' : 'error' };
    case 'rolled_back':
      // The production graph is refetched separately; drop the green overlays so the attack path shows again.
      return {
        ...state,
        highlights: state.highlights.filter((h) => h.style !== 'quarantined' && h.style !== 'proof'),
        graphVersion: state.graphVersion + 1,
      };
    case 'clear':
      return { ...initialRunState(), graphVersion: state.graphVersion };
    default:
      return state;
  }
}

export function latestResult<T extends ToolResultBase>(state: RunState, name: string): T | null {
  return readResult<T>(state.results[name]);
}

export function isRunActive(state: RunState): boolean {
  return state.phase === 'starting' || state.phase === 'running';
}
