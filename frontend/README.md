# AegisGraph console (frontend)

Vite + React 19 + TypeScript console for the AegisGraph agent. It uses plain CSS and `react-force-graph-2d` for the graph. It talks to the FastAPI backend over REST and consumes run events over Server-Sent Events.

## Run

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
npm run build      # type-checks (tsc -b) then bundles into dist/
npm run preview    # serves dist/ locally
```

The dev server proxies `/api/*` to the backend at `http://127.0.0.1:8000`. Override it with `AEGIS_API_URL`. Start the backend first with `python -m aegis api` from `backend/`, with FalkorDB running (`docker compose up -d`). The header links to the FalkorDB Browser at `http://localhost:3000`.

## What the console shows

- **Left panel:**
  - the incidents, with their status;
  - the run mode (`auto`, `deterministic` or `llm`, where `llm` needs `OPENROUTER_API_KEY` or `ANTHROPIC_API_KEY` on the backend);
  - the alert text and the five-stage stepper;
  - the live MCP tool trace. Each call expands to its arguments, result JSON and the exact Cypher it ran.
- **Centre:** the production graph.
  - Red marks attack paths, amber the chosen chokepoint, blue critical flows that stay intact, and dashed green quarantined or isolated edges.
  - *View sandbox graph* switches to the `aegis_sim_<incident>_<id>` clone in which the fix was rehearsed.
- **Right panel:**
  - the narrative, which in LLM mode includes the model's reasoning (and which OpenRouter model answered);
  - the anchor match and the exposure paths;
  - the decision and the candidate chokepoints, with coverage, betweenness, PageRank and why each was chosen or protected;
  - the service centrality table and the sandbox proof (exposure before and after, critical flows, WCC components);
  - the action taken, with its mutations and a rollback button;
  - the code owner and PR draft, and the outcome.
- **Memory tab:** episodes, playbooks and simulations from `aegis_memory_graph`.

## Mock mode (no backend needed)

Open `http://localhost:5173/?mock=1`. The console replays `public/mock-fixture.json`, a recording of a real session captured from the live API by `scripts/record_mock_fixture.py`. The recording holds:

- graph snapshots before the run, after remediation and after rollback;
- the sandbox graph;
- all 37 run events with their timing;
- the memory graph;
- the rollback result.

Payloads go through the same normalisers as the HTTP client. Re-record after changing the backend:

```bash
.venv/Scripts/python.exe scripts/record_mock_fixture.py   # from the project root, with the API running
```

## Layout

- `src/api.ts`: typed client for every endpoint, the SSE subscriber for `/api/runs/{id}/events`, and the shared normalisers.
- `src/events.ts`: types for every run event and for graph snapshots and path objects.
- `src/tools.ts`: typed shapes of the 13 MCP tool results.
- `src/runState.ts`: reducer that folds the event stream into UI state.
- `src/components/`: header, incident and run panel, stepper, tool trace, force graph (with legend and node details), decision proof, memory.
- `src/mock/index.ts`: the replaying mock client.
- `src/styles.css`: the only stylesheet (dark theme, CSS variables, safe at phone width).
