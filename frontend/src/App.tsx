import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import type { AegisClient, GraphOverview, HealthResponse, IncidentSummary, MemoryOverview, ToolInfo } from './api';
import { ApiError, createHttpClient, describeError } from './api';
import Banner from './components/Banner';
import type { RollbackOutcome } from './components/DecisionCard';
import GraphView from './components/GraphView';
import Header from './components/Header';
import IncidentPanel from './components/IncidentPanel';
import type { ProofTab } from './components/ProofPanel';
import ProofPanel from './components/ProofPanel';
import Stepper from './components/Stepper';
import ToolTrace from './components/ToolTrace';
import type { GraphNode, GraphSnapshot, RunMode } from './events';
import { createMockClient } from './mock';
import { initialRunState, isRunActive, runReducer } from './runState';

const MOCK = new URLSearchParams(window.location.search).get('mock') === '1';
const HEALTH_POLL_MS = 20000;

type GraphViewState = { kind: 'prod' } | { kind: 'sandbox'; name: string };

interface Notice {
  tone: 'ok' | 'info' | 'warn' | 'error';
  title: string;
  detail?: string;
}

function healthBanner(error: ApiError): { title: string; detail: string } {
  if (error.status === 503) {
    return {
      title: 'FalkorDB is unreachable',
      detail: `The backend answered 503: ${error.message}. Start the database with "docker compose up -d", then reseed.`,
    };
  }
  if (error.status === 0) {
    return {
      title: 'Backend API is not responding',
      detail: `${error.message} Start it with "python -m aegis api" from backend/, or open this page with ?mock=1 to preview with sample data.`,
    };
  }
  return { title: `Health check failed (HTTP ${error.status})`, detail: error.message };
}

export default function App() {
  const client = useMemo<AegisClient>(() => (MOCK ? createMockClient() : createHttpClient()), []);

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState<ApiError | null>(null);
  const [overview, setOverview] = useState<GraphOverview | null>(null);
  const [tools, setTools] = useState<ToolInfo[]>([]);

  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [incidentsLoading, setIncidentsLoading] = useState(true);
  const [incidentsError, setIncidentsError] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [alertText, setAlertText] = useState('');
  const [mode, setMode] = useState<RunMode>('auto');

  const [prodGraph, setProdGraph] = useState<GraphSnapshot | null>(null);
  const [graphLoading, setGraphLoading] = useState(true);
  const [graphError, setGraphError] = useState<string | null>(null);
  const [view, setView] = useState<GraphViewState>({ kind: 'prod' });
  const [sandboxGraph, setSandboxGraph] = useState<GraphSnapshot | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const [memory, setMemory] = useState<MemoryOverview | null>(null);
  const [memoryLoading, setMemoryLoading] = useState(false);
  const [memoryError, setMemoryError] = useState<string | null>(null);
  const [tab, setTab] = useState<ProofTab>('proof');

  const [run, dispatch] = useReducer(runReducer, undefined, initialRunState);
  const [rollback, setRollback] = useState<RollbackOutcome | null>(null);
  const [rollbackBusy, setRollbackBusy] = useState(false);
  const [reseeding, setReseeding] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);

  const unsubscribeRef = useRef<(() => void) | null>(null);
  const pollTimerRef = useRef<number | null>(null);
  const pollGenRef = useRef(0);

  /* ---------------------------------------------------------------- */
  /* Data loading                                                      */
  /* ---------------------------------------------------------------- */

  const loadHealth = useCallback(async () => {
    try {
      const next = await client.health();
      setHealth(next);
      setHealthError(null);
    } catch (error) {
      setHealth(null);
      setHealthError(error instanceof ApiError ? error : new ApiError(0, describeError(error)));
    }
  }, [client]);

  const loadOverview = useCallback(async () => {
    try {
      setOverview(await client.graphs());
    } catch {
      setOverview(null);
    }
  }, [client]);

  const loadTools = useCallback(async () => {
    try {
      setTools(await client.tools());
    } catch {
      setTools([]);
    }
  }, [client]);

  const loadIncidents = useCallback(async () => {
    setIncidentsLoading(true);
    try {
      const list = await client.incidents();
      setIncidents(list);
      setIncidentsError(null);
      setSelectedIncidentId((current) => {
        if (current && list.some((i) => i.id === current)) return current;
        const open = list.find((i) => i.status.toUpperCase() === 'OPEN');
        return open?.id ?? list[0]?.id ?? null;
      });
    } catch (error) {
      setIncidentsError(describeError(error));
    } finally {
      setIncidentsLoading(false);
    }
  }, [client]);

  const loadGraph = useCallback(async () => {
    setGraphLoading(true);
    try {
      setProdGraph(await client.graph());
      setGraphError(null);
    } catch (error) {
      setGraphError(describeError(error));
    } finally {
      setGraphLoading(false);
    }
  }, [client]);

  const loadMemory = useCallback(async () => {
    setMemoryLoading(true);
    try {
      setMemory(await client.memory());
      setMemoryError(null);
    } catch (error) {
      setMemoryError(describeError(error));
    } finally {
      setMemoryLoading(false);
    }
  }, [client]);

  const loadEverything = useCallback(() => {
    void loadHealth();
    void loadOverview();
    void loadTools();
    void loadIncidents();
    void loadGraph();
    void loadMemory();
  }, [loadHealth, loadOverview, loadTools, loadIncidents, loadGraph, loadMemory]);

  useEffect(() => {
    loadEverything();
    const timer = window.setInterval(() => void loadHealth(), HEALTH_POLL_MS);
    return () => window.clearInterval(timer);
  }, [loadEverything, loadHealth]);

  useEffect(() => () => unsubscribeRef.current?.(), []);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(null), 7000);
    return () => window.clearTimeout(timer);
  }, [notice]);

  // Prefill the alert box from the selected incident (DESIGN.md §7).
  const prefilledFor = useRef<string | null>(null);
  useEffect(() => {
    const incident = incidents.find((i) => i.id === selectedIncidentId);
    if (incident && incident.id !== prefilledFor.current) {
      setAlertText(incident.raw_alert);
      prefilledFor.current = incident.id;
    }
  }, [selectedIncidentId, incidents]);

  // Refetch the production graph after execute_remediation / rollback_remediation (DESIGN.md §7).
  useEffect(() => {
    if (run.graphVersion === 0) return;
    void loadGraph();
    void loadIncidents();
    void loadOverview();
  }, [run.graphVersion, loadGraph, loadIncidents, loadOverview]);

  useEffect(() => {
    if (run.phase !== 'completed' && run.phase !== 'error') return;
    void loadMemory();
    void loadIncidents();
    void loadOverview();
    void loadHealth();
  }, [run.phase, loadMemory, loadIncidents, loadOverview, loadHealth]);

  /* ---------------------------------------------------------------- */
  /* Actions                                                           */
  /* ---------------------------------------------------------------- */

  const stopPolling = () => {
    pollGenRef.current += 1;
    if (pollTimerRef.current !== null) {
      window.clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  };

  const pollRun = useCallback(
    (runId: string) => {
      const generation = pollGenRef.current;
      let seen = 0;
      const tick = async () => {
        try {
          const record = await client.run(runId);
          if (pollGenRef.current !== generation) return; // cancelled while the request was in flight
          if (seen === 0) dispatch({ type: 'start', runId });
          for (const event of record.events.slice(seen)) dispatch({ type: 'event', event });
          seen = record.events.length;
          if (record.status === 'running') {
            pollTimerRef.current = window.setTimeout(() => void tick(), 2000);
          } else {
            dispatch({ type: 'stream_done' });
          }
        } catch (error) {
          if (pollGenRef.current === generation) dispatch({ type: 'stream_error', message: describeError(error) });
        }
      };
      void tick();
    },
    [client],
  );

  const startRun = async () => {
    if (!selectedIncidentId || isRunActive(run)) return;
    unsubscribeRef.current?.();
    stopPolling();
    setRollback(null);
    setSelectedNode(null);
    setView({ kind: 'prod' });
    setTab('proof');
    dispatch({ type: 'starting' });
    try {
      const { run_id } = await client.startRun({
        incident_id: selectedIncidentId,
        alert_text: alertText.trim() || undefined,
        mode,
      });
      if (!run_id) throw new Error('The backend did not return a run_id');
      dispatch({ type: 'start', runId: run_id });
      unsubscribeRef.current = client.subscribeRunEvents(run_id, {
        onEvent: (event) => dispatch({ type: 'event', event }),
        onReplay: () => dispatch({ type: 'start', runId: run_id }),
        onDone: () => dispatch({ type: 'stream_done' }),
        onError: (error) => {
          dispatch({ type: 'stream_error', message: `${error.message}. Falling back to polling /api/runs/${run_id}.` });
          pollRun(run_id);
        },
      });
    } catch (error) {
      dispatch({ type: 'stream_error', message: describeError(error) });
    }
  };

  const handleReseed = async () => {
    setReseeding(true);
    try {
      const counts = await client.seed({});
      unsubscribeRef.current?.();
      stopPolling();
      dispatch({ type: 'clear' });
      setRollback(null);
      setView({ kind: 'prod' });
      setSelectedNode(null);
      const total = Object.values(counts).reduce((sum, n) => sum + n, 0);
      setNotice({ tone: 'ok', title: 'Graph reseeded', detail: total > 0 ? `${total} nodes across ${Object.keys(counts).length} labels.` : undefined });
      loadEverything();
    } catch (error) {
      setNotice({ tone: 'error', title: 'Reseed failed', detail: describeError(error) });
    } finally {
      setReseeding(false);
    }
  };

  const handleRollback = async (auditId: string) => {
    setRollbackBusy(true);
    try {
      const result = await client.rollback(auditId);
      dispatch({ type: 'rolled_back' });
      if (result.status === 'ALREADY_ROLLED_BACK') {
        setRollback({ auditId, status: 'ok', message: 'Already rolled back earlier; nothing to restore.' });
        setNotice({ tone: 'info', title: `${auditId} was already rolled back`, detail: 'The graph has been refreshed.' });
      } else {
        const skipped = result.skipped?.length ? `, ${result.skipped.length} left in place (changed since or owned by another action)` : '';
        setRollback({ auditId, status: 'ok', message: `${result.status}: incident ${result.incident_status ?? 'unchanged'}, ${result.restored.length} mutations restored${skipped}.` });
        setNotice({ tone: 'ok', title: `Rolled back ${auditId}`, detail: 'Edge statuses and node states restored; exposure paths are active again.' });
      }
    } catch (error) {
      setRollback({ auditId, status: 'error', message: describeError(error) });
    } finally {
      setRollbackBusy(false);
    }
  };

  const viewSandbox = async (name: string) => {
    setGraphLoading(true);
    try {
      const snapshot = await client.graphByName(name);
      setSandboxGraph(snapshot);
      setView({ kind: 'sandbox', name });
      setSelectedNode(null);
      setGraphError(null);
    } catch (error) {
      setNotice({ tone: 'error', title: `Could not load sandbox ${name}`, detail: describeError(error) });
    } finally {
      setGraphLoading(false);
    }
  };

  const backToProduction = () => {
    setView({ kind: 'prod' });
    setSelectedNode(null);
  };

  /* ---------------------------------------------------------------- */
  /* Render                                                            */
  /* ---------------------------------------------------------------- */

  const running = isRunActive(run);
  const llmConfigured = health?.llm_configured ?? false;
  const startBlockedReason = !selectedIncidentId
    ? 'Select an incident first.'
    : reseeding
      ? 'The graph is being reseeded.'
      : healthError && !MOCK
      ? 'The backend is unavailable.'
      : mode === 'llm' && !llmConfigured
        ? 'LLM mode is not configured on the backend.'
        : null;
  const visibleSnapshot = view.kind === 'sandbox' ? sandboxGraph : prodGraph;
  const banner = healthError ? healthBanner(healthError) : null;

  return (
    <div className="app">
      <Header
        health={health}
        healthError={healthError ? healthError.message : null}
        overview={overview}
        snapshot={prodGraph}
        mock={MOCK}
        reseeding={reseeding}
        running={isRunActive(run)}
        onReseed={() => void handleReseed()}
      />

      <div className="banners">
        {banner ? (
          <Banner tone="error" title={banner.title} detail={banner.detail} action={{ label: 'Retry', onClick: () => void loadHealth() }} />
        ) : null}
        {health && !health.falkordb && !healthError ? (
          <Banner tone="warn" title="FalkorDB reported degraded" detail="The API is up but FalkorDB did not answer the ping. Graph-backed actions will fail until it recovers." />
        ) : null}
        {run.streamError ? <Banner tone={run.phase === 'error' ? 'error' : 'warn'} title="Event stream problem" detail={run.streamError} /> : null}
        {notice ? <Banner tone={notice.tone} title={notice.title} detail={notice.detail} onDismiss={() => setNotice(null)} /> : null}
      </div>

      <main className="workspace">
        <aside className="panel panel--left" aria-label="Incidents and run">
          <IncidentPanel
            incidents={incidents}
            loading={incidentsLoading}
            error={incidentsError}
            selectedId={selectedIncidentId}
            onSelect={setSelectedIncidentId}
            mode={mode}
            onModeChange={setMode}
            llmConfigured={llmConfigured}
            alertText={alertText}
            onAlertChange={setAlertText}
            onStart={() => void startRun()}
            running={running}
            startBlockedReason={startBlockedReason}
            tools={tools}
          />
          <Stepper stages={run.stages} phase={run.phase} />
          <ToolTrace rows={run.trace} phase={run.phase} />
        </aside>

        <section className="stage" aria-label="Graph">
          <GraphView
            snapshot={visibleSnapshot}
            loading={graphLoading && !visibleSnapshot}
            error={view.kind === 'prod' ? graphError : null}
            highlights={run.highlights}
            selectedNodeId={selectedNode?.id ?? null}
            onSelectNode={setSelectedNode}
            viewingSandbox={view.kind === 'sandbox'}
            onBackToProduction={backToProduction}
          />
        </section>

        <aside className="panel panel--right" aria-label="Decision proof">
          <ProofPanel
            run={run}
            tab={tab}
            onTabChange={setTab}
            memory={memory}
            memoryLoading={memoryLoading}
            memoryError={memoryError}
            onRefreshMemory={() => void loadMemory()}
            rollback={rollback}
            rollbackBusy={rollbackBusy}
            onRollback={(auditId) => void handleRollback(auditId)}
            onViewSandbox={(name) => void viewSandbox(name)}
            viewingSandbox={view.kind === 'sandbox'}
          />
        </aside>
      </main>
    </div>
  );
}
