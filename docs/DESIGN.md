# AegisGraph — Design Contract

This is the design contract AegisGraph was built against, kept current with the implementation.
It records (1) facts verified against the live stack, (2) the graph data model and seed dataset,
(3) the MCP tool contract, (4) the agent/event contract, (5) the REST/SSE API contract, (6) the frontend spec,
(7) testing rules. Everything in §1 was executed successfully against FalkorDB 6.0.2 on 2026-10-14.

Project root: `D:\Graph hack\aegisgraph` (Windows 11, Git Bash + PowerShell available).
Python venv: `.venv` (Python 3.12). Run Python as `./.venv/Scripts/python.exe` from the project root, with
`cwd=backend` for anything importing `aegis` (or set `PYTHONPATH=backend`). Node 24 / npm 11 for the frontend.
FalkorDB runs via `docker compose up -d` (container `aegis-falkordb`, ports 6379 + 3000 browser UI).

Hackathon context: Graph Hacks (WeMakeDevs x FalkorDB), Track 01 "Agents That Act on Connected Data".
Judging pillars: multi-hop reasoning; graph queries + algorithms as agent tools; tool selection through MCP;
actions based on what the graph shows; explainable results. Rule 3: if the product still works with FalkorDB
removed, it is disqualified — every decision must come from graph queries/algorithms.

---

## 1. Verified platform facts

### 1.1 FalkorDB 6.0.2 Cypher (all executed OK unless marked)

| Feature | Verified syntax |
|---|---|
| Range index | `CREATE INDEX FOR (n:Label) ON (n.prop)` — creating it twice raises `Attribute 'prop' is already indexed` (catch and ignore) |
| Vector index | `CREATE VECTOR INDEX FOR (n:Label) ON (n.embedding) OPTIONS {dimension: 384, similarityFunction: 'cosine', M: 16, efConstruction: 200}` |
| Vector literal / param | `vecf32([0.1, 0.2, ...])` and `vecf32($vec)` with a Python `list[float]` param |
| Vector KNN | `CALL db.idx.vector.queryNodes('Label', 'embedding', $k, vecf32($vec)) YIELD node, score` — **score is a distance (lower = more similar; identical ≈ 0.0)** |
| Full-text index | `CREATE FULLTEXT INDEX FOR (n:Label) ON (n.summary)` (**the procedure form `db.idx.fulltext.createNodeIndex('L','p')` FAILS on 6.x** — do not use it) |
| Full-text query | `CALL db.idx.fulltext.queryNodes('Label', $text) YIELD node, score` — score higher = better; fuzzy `%term%` supported |
| PageRank | `CALL algo.pageRank('Service', 'ROUTES_TO') YIELD node, score` |
| Betweenness | `CALL algo.betweenness({nodeLabels: ['Service'], relationshipTypes: ['ROUTES_TO']}) YIELD node, score` (directed) |
| WCC | `CALL algo.WCC({nodeLabels: ['Service'], relationshipTypes: ['ROUTES_TO']}) YIELD node, componentId` — **cannot filter by edge property; in the sandbox DELETE edges to simulate severing** |
| Label propagation | `CALL algo.labelPropagation({nodeLabels: [...], relationshipTypes: [...]}) YIELD node, communityId` |
| BFS | `MATCH (s:Service {name: $name}) CALL algo.BFS(s, $depth, 'ROUTES_TO') YIELD nodes, edges` (3rd arg may be `NULL` for any type; `nodes` excludes the source) |
| Shortest paths | `MATCH (src), (dst) CALL algo.SPpaths({sourceNode: src, targetNode: dst, relTypes: ['ROUTES_TO','ASSUMES_ROLE','CAN_ACCESS'], maxLen: 6}) YIELD path, pathWeight` (**no `pathLen` yield**; use `length(path)`) |
| Single-source paths | `CALL algo.SSpaths({sourceNode: src, relTypes: [...], maxLen: 6, pathCount: 10}) YIELD path, pathWeight` |
| Other algos available | `algo.HarmonicCentrality`, `algo.MSF`, `algo.maxFlow` |
| Variable-length + edge filter | `MATCH p=(a)-[:ROUTES_TO*0..3]->(b) WHERE ALL(r IN relationships(p) WHERE coalesce(r.status,'ACTIVE') = 'ACTIVE')` |
| shortestPath() | `RETURN length(shortestPath((a)-[:ROUTES_TO*]->(b)))` works |
| Procedures list | `CALL dbms.procedures() YIELD name` ; indexes: `CALL db.indexes() YIELD label, properties, types` |
| Graph copy | Redis command `GRAPH.COPY <src> <dst>` (python: `db.connection.execute_command("GRAPH.COPY", src, dst)` or `Graph.copy(clone)`) — copies nodes, edges and indexes; errors if dst exists |
| Graph list | `db.list_graphs()` / `GRAPH.LIST` |
| Params | nested lists of maps work: `UNWIND $rows AS row MERGE (n:T {id: row.id}) SET n.summary = row.summary` |

### 1.2 falkordb-py 1.7.1
`FalkorDB(host, port, username=None, password=None)`; `db.select_graph(name)`; `graph.query(q, params=..., timeout=...)` → `QueryResult` with `.result_set`, `.header`, `.run_time_ms`, `.nodes_created`, `.relationships_created`, `.properties_set`, ...; `graph.ro_query(...)` is server-enforced read-only; `graph.delete()` raises `ResponseError('Invalid graph operation on empty key')` for a missing graph; `graph.copy(clone_name)`. Node/Edge/Path objects as documented in `backend/aegis/graph.py`. The client is synchronous (redis-py).

### 1.3 MCP python SDK 2.3.0 (**v2 API, not FastMCP**)
```python
from mcp.server.mcpserver import MCPServer          # FastMCP was renamed in 2.x
server = MCPServer(name="aegisgraph", instructions="...")
@server.tool()                                      # schema auto-generated from type hints + docstring
def trace_blast_radius(cve_id: str, max_route_hops: int = 3) -> dict: ...
server.run(transport="stdio")                       # synchronous; logs must go to stderr, never stdout
```
Client:
```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client, get_default_environment
params = StdioServerParameters(command=sys.executable, args=["-m", "aegis.mcp_server"], cwd=str(BACKEND_DIR),
                               env={**get_default_environment(), **settings.env_for_subprocess()})
async with stdio_client(params) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
        tools = (await session.list_tools()).tools      # each has .name, .description, .input_schema (snake_case in 2.x)
        res = await session.call_tool("trace_blast_radius", {"cve_id": "CVE-2026-8841"})
        # res.is_error, res.content (list; TextContent has .text), res.structured_content (dict when the tool returns a dict)
```
`get_default_environment()` only forwards a minimal env on Windows (PATH, SYSTEMROOT, ...) so FalkorDB/AEGIS vars must be passed explicitly (see `Settings.env_for_subprocess`). The official FalkorDB MCP server is installed at `mcp/falkordb-mcpserver/node_modules/@falkordb/mcpserver/dist/index.js` (run with `node`, env `FALKORDB_HOST`, `FALKORDB_PORT`); it is optional (`AEGIS_ENABLE_FALKORDB_MCP`).

### 1.4 Anthropic python SDK 1.13.0 (LLM mode)
- Model default `claude-opus-5-5` (env `AEGIS_LLM_MODEL`). Thinking is always on for this model; pass `thinking={"type": "adaptive", "display": "summarized"}` to receive readable thinking summaries; depth via `output_config={"effort": settings.llm_effort}` (`low|medium|high|xhigh|max`).
- Use streaming: `with client.beta.messages.stream(model=..., max_tokens=16000, system=[{"type":"text","text":SYSTEM,"cache_control":{"type":"ephemeral"}}], tools=[...], messages=[...], thinking=..., output_config=..., betas=["server-side-fallback-2026-07-01"], fallbacks="default") as stream:` then iterate `stream.text_stream` or events, and `stream.get_final_message()`.
  Verified that `client.beta.messages.stream` accepts `fallbacks`, `betas`, `output_config`, `thinking`, `tools`, `system`, `cache_control`.
- Manual agentic loop (we need custom SSE event emission): append `{"role":"assistant","content":response.content}`, then one user message with ALL `tool_result` blocks (`{"type":"tool_result","tool_use_id":block.id,"content":json_text,"is_error":bool}`). Loop while `stop_reason == "tool_use"`; stop on `end_turn`; on `max_tokens` never run the (possibly truncated) tool calls: answer each with an `is_error` result and ask the model to continue with the same budget, ending the run on a second consecutive truncation; on `pause_turn` resend; on `refusal` **never execute that turn's tools** and finish the run with an error event. Cap iterations at `settings.max_tool_iterations`.
- Never use `tool_choice: any/tool` (400 on this model); steer with the prompt. `strict` is optional; MCP schemas lack `additionalProperties: false`, so leave `strict` off.
- Tool definitions for the API are built from MCP: `{"name": t.name, "description": t.description, "input_schema": t.input_schema}`.
- Always parse `block.input` as a dict (SDK gives a dict); never string-match serialized JSON.
- Error chain to catch, most specific first: `anthropic.AuthenticationError`, `anthropic.RateLimitError`, `anthropic.APIStatusError`, `anthropic.APIConnectionError`.


### 1.5 OpenRouter (LLM mode, free models only)
- `POST https://openrouter.ai/api/v1/chat/completions` (OpenAI-compatible), called with httpx in `aegis/llm_openrouter.py`. Request: `messages` (system, user, assistant with `tool_calls`, `role: tool` results with `tool_call_id`), `tools` (`{"type": "function", "function": {name, description, parameters}}`), `tool_choice: "auto"`, `max_completion_tokens`, optional `reasoning: {effort}`, and `models: [primary, ...fallbacks]` (OpenRouter tries the next model on any error, including rate limits; the response `model` names the one that answered).
- Response: `choices[0].message.{content, reasoning, reasoning_details, tool_calls[{id, type, function: {name, arguments (JSON string)}}], refusal}` and `finish_reason` in `tool_calls | stop | length | content_filter | error`; errors as `{"error": {code, message, metadata}}`, sometimes with HTTP 200.
- Free-model limits: 20 requests/minute; 50 requests/day without purchased credits (1,000 with at least 10 credits); HTTP 429 when exceeded.
- Free-only enforcement: models must be priced at zero on the public `GET /api/v1/models` list (fallback rule when it is unreachable: IDs ending in `:free`, or `openrouter/free`).

---

## 2. Repository layout

```
aegisgraph/
├── docker-compose.yml          FalkorDB + browser
├── .env.example / .gitignore / requirements.txt
├── README.md                   submission README
├── docs/
│   ├── DESIGN.md               this file
│   ├── GRAPH_MODEL.md          nodes/edges/indexes + why
│   ├── CYPHER_QUERIES.md       every query/algorithm the product runs (generated by scripts/export_cypher.py)
│   └── ARCHITECTURE.md         agent loop, MCP topology, sandbox simulation, memory
├── backend/
│   ├── aegis/
│   │   ├── __init__.py, config.py, graph.py
│   │   ├── embeddings.py       local 384-dim hashing embedding
│   │   ├── seed.py             seeds <prefix>prod_graph + indexes + a historical mitigated incident
│   │   ├── memory.py           <prefix>memory_graph: episodes, tool calls, simulations, playbooks
│   │   ├── tools.py            the 13 graph tools as plain functions returning dicts
│   │   ├── mcp_server.py       MCPServer exposing tools.py over stdio
│   │   ├── mcp_client.py       async client: spawn server(s), list/call tools
│   │   ├── agent.py            orchestrator: deterministic + LLM modes, emits events
│   │   ├── api.py              FastAPI app: REST + SSE
│   │   └── __main__.py         CLI: seed | mcp | run | api
│   └── tests/                  pytest, live FalkorDB, prefix test_aegis_
├── frontend/                   Vite + React + TypeScript console
├── mcp/falkordb-mcpserver/     pinned official FalkorDB MCP server
└── scripts/                    run_backend.ps1 / run_backend.sh / export_cypher.py / record_mock_fixture.py
```

Conventions: Python 3.12, type hints, `from __future__ import annotations`, docstrings on every tool (the MCP
tool description is the docstring: state WHEN the agent should call it, what it returns, and which FalkorDB
feature it uses). Logging via `logging` to stderr only. No `print` in modules imported by the MCP server
(stdout is the MCP transport). Every tool result dict includes `"cypher": [trace.as_dict(), ...]` (the exact
queries executed, from `graph.CypherTrace`) and `"duration_ms"`.

---

## 3. Graph data model

### 3.1 Production graph `<prefix>prod_graph`

| Label | Properties | Indexes |
|---|---|---|
| `Vulnerability` | `id` (CVE), `severity`, `cvss` (float), `summary`, `published`, `embedding` (vecf32[384]) | RANGE `id`; VECTOR `embedding` (384, cosine); FULLTEXT `summary` |
| `Package` | `name`, `version`, `fixed_version`, `ecosystem` | RANGE `name` |
| `Function` | `id`, `name`, `file_path`, `repo_name`, `embedding` (vecf32[384]) | RANGE `id`; VECTOR `embedding` |
| `Service` | `id`, `name`, `tier` (`critical`/`standard`), `status` (`HEALTHY`/`DEGRADED`/`ISOLATED`), `rps` (int) | RANGE `id`, `name` |
| `IAMRole` | `arn`, `name`, `privilege_level` (`ADMIN`/`SCOPED`/`READONLY`), `status` (`ACTIVE`/`QUARANTINED`) | RANGE `name` |
| `Database` | `id`, `name`, `contains_pii` (bool), `classification` | RANGE `name` |
| `Developer` | `id`, `name`, `handle`, `team`, `on_call` (bool) | RANGE `handle` |
| `Incident` | `id`, `timestamp` (int epoch), `title`, `raw_alert`, `status` (`OPEN`/`MITIGATED`) | RANGE `id` |
| `ActionAudit` | `id`, `timestamp`, `action_type`, `target_entity`, `bridge_service`, `iam_role`, `betweenness_score`, `pagerank_score`, `sim_passed` (bool), `simulation_id`, `cypher_proof` (JSON string), `proof_paths` (JSON string), `mutations` (JSON string), `assigned_developer`, `pr_url`, `justification`, `rolled_back` (bool), `mode` | RANGE `id` |

| Relationship | Properties |
|---|---|
| `(Vulnerability)-[:AFFECTS]->(Package)` | `exploitability` |
| `(Function)-[:IMPORTS]->(Package)` | `line_number` |
| `(Function)-[:CALLS]->(Function)` | `call_frequency` |
| `(Developer)-[:MAINTAINED]->(Function)` | `commits_count`, `last_touched` |
| `(Service)-[:DEPLOYS_CODE]->(Function)` | `commit_sha` |
| `(Service)-[:ROUTES_TO]->(Service)` | `status` (`ACTIVE`/`ISOLATED_BY_AEGIS`), `is_critical_path` (bool), `protocol` |
| `(Service)-[:ASSUMES_ROLE]->(IAMRole)` | `scope` |
| `(IAMRole)-[:CAN_ACCESS]->(Database)` | `status` (`ACTIVE`/`QUARANTINED_BY_AEGIS`), `access_mode` (`READ`/`WRITE`/`ADMIN`) |
| `(Incident)-[:TRIGGERED_ON]->(Vulnerability)` | `detected_at`, `confidence` |
| `(Incident)-[:RESOLVED_BY]->(ActionAudit)` | `execution_time_ms` |
| `(ActionAudit)-[:MODIFIED_ENTITY]->(IAMRole \| Service)` | `previous_state`, `new_state`, `entity_kind` |

"Exposure" definition used everywhere (tools, sandbox, verification): an **active attack path**
`(origin:Service)-[:ROUTES_TO*0..N]->(pivot:Service)-[:ASSUMES_ROLE]->(role:IAMRole)-[:CAN_ACCESS]->(db:Database {contains_pii: true})`
where `origin` deploys a Function that IMPORTS a Package AFFECTED by the CVE, and every relationship on the path
has `coalesce(r.status,'ACTIVE') = 'ACTIVE'`. Remediation makes exposure paths disappear by flipping edge
`status` (surgical, reversible) — not by deleting anything in production.

### 3.2 Seed dataset (deterministic; `seed.py` must create exactly this)

Services (10): `api-edge-gateway` (critical, rps 14200), `auth-token-service` (critical, 9800), `checkout-gateway` (critical, 5400), `payment-orchestrator` (critical, 3100), `inventory-service` (critical, 2600), `notification-service` (standard, 900), `telemetry-audit-sync` (standard, 1200), `legacy-billing-bridge` (standard, 180), `reporting-adapter` (standard, 240), `search-indexer` (standard, 700). ids `svc-<slug>`.

ROUTES_TO (all `status: 'ACTIVE'`): edge→auth (critical), edge→checkout (critical), edge→search-indexer (no), checkout→auth (critical), checkout→payment (critical), checkout→inventory (critical), payment→telemetry (no), payment→notification (no), auth→legacy-billing-bridge (no), legacy-billing-bridge→payment (no), legacy-billing-bridge→reporting-adapter (no), inventory→telemetry (no), reporting-adapter→telemetry (no), search-indexer→inventory (no).

IAM roles (4): `LegacyBillingBridgeAdmin` (ADMIN) ← ASSUMES_ROLE legacy-billing-bridge; `PaymentReadWriteRole` (SCOPED) ← payment-orchestrator, telemetry-audit-sync; `ReportingReadOnly` (READONLY) ← reporting-adapter; `InventoryWriter` (SCOPED) ← inventory-service. arn `arn:aws:iam::992100:role/<name>`.

Databases (5): `customer-kyc-vault-db` (pii, RESTRICTED_PII), `global-settlement-ledger` (pii, FINANCIAL_CORE), `reporting-warehouse` (pii, INTERNAL_ANALYTICS), `prometheus-archive-store` (no pii, INTERNAL_TELEMETRY), `product-catalog-db` (no pii, INTERNAL).
CAN_ACCESS (ACTIVE): LegacyBillingBridgeAdmin→kyc-vault (ADMIN), →ledger (ADMIN); PaymentReadWriteRole→ledger (WRITE), →prometheus (WRITE); ReportingReadOnly→reporting-warehouse (READ); InventoryWriter→product-catalog (WRITE).

Packages (6): `jwt-crypto-core` 2.4.1 (fixed 2.4.2, pip), `legacy-sql-adapter` 0.9.3 (fixed 1.0.0, pip), `yaml-loader` 5.1.0 (fixed 5.4.1, pip), `image-resizer` 1.2.0 (fixed 1.2.3, npm), `redis-session-pool` 1.9.0 (fixed 1.9.0, pip), `http-retry` 3.0.0 (fixed 3.0.0, npm).

Vulnerabilities (4): `CVE-2026-8841` CRITICAL 9.8 "Remote token forgery and deserialization bypass in jwt-crypto-core allows unauthenticated attackers to mint valid bearer tokens" → AFFECTS jwt-crypto-core; `CVE-2026-4102` HIGH 8.1 "SQL injection in legacy-sql-adapter reporting query builder" → legacy-sql-adapter; `CVE-2026-2210` HIGH 7.5 "Unsafe YAML deserialization in yaml-loader leads to remote code execution" → yaml-loader; `CVE-2026-0193` MEDIUM 5.3 "Denial of service via crafted PNG in image-resizer" → image-resizer.

Functions (12, ids `fn_<slug>`): `verify_bearer_token()` (core-auth-service, src/auth/token_validator.py, IMPORTS jwt-crypto-core), `issue_session_token()` (core-auth-service, src/auth/session_issuer.py, IMPORTS jwt-crypto-core + redis-session-pool), `validate_checkout_session()` (checkout-gateway, src/checkout/session_guard.py, CALLS verify_bearer_token), `settle_merchant_payout()` (payment-orchestrator, src/ledger/payout_worker.py, CALLS validate_checkout_session), `reconcile_legacy_invoices()` (legacy-billing-bridge, src/billing/reconcile.py, IMPORTS legacy-sql-adapter), `build_report()` (reporting-adapter, src/reports/builder.py, IMPORTS legacy-sql-adapter), `parse_config()` (search-indexer, src/config/loader.py, IMPORTS yaml-loader), `index_products()` (search-indexer, src/index/products.py, CALLS parse_config), `resize_avatar()` (notification-service, src/media/avatar.ts, IMPORTS image-resizer), `retry_dispatch()` (notification-service, src/dispatch/retry.ts, IMPORTS http-retry), `sync_metrics()` (telemetry-audit-sync, src/metrics/sync.py), `reserve_stock()` (inventory-service, src/stock/reserve.py).
DEPLOYS_CODE: auth-token-service→verify_bearer_token, issue_session_token; checkout-gateway→validate_checkout_session; payment-orchestrator→settle_merchant_payout; legacy-billing-bridge→reconcile_legacy_invoices; reporting-adapter→build_report; search-indexer→parse_config, index_products; notification-service→resize_avatar, retry_dispatch; telemetry-audit-sync→sync_metrics; inventory-service→reserve_stock.

Developers (5): Aarav Mehta `@aarav-sec` (Identity & Core Auth, on_call true) MAINTAINED verify_bearer_token (84 commits), issue_session_token (52); Priya Nair `@priya-payments` (Checkout & Ledger, false) → validate_checkout_session (61), settle_merchant_payout (49); Rohan Iyer `@rohan-platform` (Platform, true) → reconcile_legacy_invoices (33), build_report (27), sync_metrics (19); Meera Krishnan `@meera-infra` (Infrastructure, false) → parse_config (41), index_products (38), retry_dispatch (12); Dev Patel `@dev-growth` (Growth, false) → resize_avatar (22), reserve_stock (30).

Incidents: `INC-2026-091` OPEN, title "Anomalous JWT token forgery attempt targeting api-edge-gateway", raw_alert "WAF observed 1,240 bearer tokens with forged kid headers accepted by auth-token-service in 4 minutes; signature verification bypass suspected in jwt-crypto-core (deserialization path)", TRIGGERED_ON CVE-2026-8841.
`INC-2026-077` MITIGATED (timestamp 9 days earlier), title "SQLi probe against reporting-adapter via legacy-sql-adapter", TRIGGERED_ON CVE-2026-4102, with an existing `ActionAudit` `AUDIT-SEED-077` (action_type `SURGICAL_ROLE_QUARANTINE_AND_OWNER_PR`, bridge_service `reporting-adapter`, iam_role `ReportingReadOnly`, sim_passed true, assigned_developer `@rohan-platform`, rolled_back false) linked RESOLVED_BY and MODIFIED_ENTITY→ReportingReadOnly (previous_state ACTIVE, new_state QUARANTINED) — **but keep ReportingReadOnly's live status ACTIVE and its CAN_ACCESS edges ACTIVE** (the historical incident was later rolled back/ratified; it exists so `recall_similar_incidents` has an episode to return on a fresh database). Also seed one memory-graph `Playbook` for it (see §4).

Expected demo facts (tests assert these): for CVE-2026-8841 the origin service is exactly `auth-token-service` (it deploys both functions that import jwt-crypto-core). With `ROUTES_TO*0..3` there are **6 exposure paths**, every one of them passing through `legacy-billing-bridge`: legacy→LegacyBillingBridgeAdmin→customer-kyc-vault-db (1 route hop), legacy→LegacyBillingBridgeAdmin→global-settlement-ledger (1), legacy→payment→PaymentReadWriteRole→global-settlement-ledger (2), legacy→reporting-adapter→ReportingReadOnly→reporting-warehouse (2), legacy→payment→telemetry→PaymentReadWriteRole→global-settlement-ledger (3), legacy→reporting-adapter→telemetry→PaymentReadWriteRole→global-settlement-ledger (3). Exposed PII databases = {customer-kyc-vault-db, global-settlement-ledger, reporting-warehouse}; pivot services = {legacy-billing-bridge, payment-orchestrator, reporting-adapter, telemetry-audit-sync}; the non-critical pivots are legacy-billing-bridge (betweenness 6.0, the highest of all services), reporting-adapter (1.0) and telemetry-audit-sync (0, a sink); payment-orchestrator is the runner-up (5.83); payment-orchestrator is critical-tier and must never be isolated. The chosen remediation is therefore bridge=`legacy-billing-bridge`, role=`LegacyBillingBridgeAdmin`; the sandbox proves exposure 6 → 0 with all four critical flows intact and every critical service in one WCC component (legacy becomes its own component); after execution the live exposure count is 0; after rollback it is 6 again. Code owner for CVE-2026-8841 is `@aarav-sec` (on call).

### 3.3 Memory graph `<prefix>memory_graph` (cross-session episodic + procedural memory)

| Label | Properties |
|---|---|
| `Episode` | `id`, `incident_id`, `cve_id`, `started_at`, `finished_at`, `mode` (`llm`/`deterministic`), `outcome` (`MITIGATED`/`NO_ACTION`/`ERROR`), `summary`, `tool_call_count` |
| `ToolCall` | `id`, `seq`, `name`, `args_json`, `result_digest` (≤300 chars), `duration_ms`, `is_error` |
| `Simulation` | `id`, `incident_id`, `cve_id`, `timestamp`, `bridge_service`, `iam_role`, `safe` (bool), `exposure_closed`, `critical_flows_intact`, `critical_services_connected`, `sandbox_graph`, `exposure_before`, `exposure_after` |
| `Playbook` | `signature` (e.g. `package:jwt-crypto-core`), `action_type`, `bridge_service`, `iam_role`, `success_count`, `last_used`, `last_incident_id` |

Edges: `(Episode)-[:USED_TOOL {seq}]->(ToolCall)`, `(Episode)-[:RAN_SIMULATION]->(Simulation)`, `(Episode)-[:APPLIED_PLAYBOOK]->(Playbook)`, `(Playbook)-[:DERIVED_FROM]->(Simulation)`.
`memory.py` API: `start_episode(incident_id, cve_id, mode) -> episode_id`, `record_tool_call(episode_id, seq, name, args, result, duration_ms, is_error)`, `record_simulation(sim_dict, episode_id|None)`, `latest_passing_simulation(incident_id, bridge_service, iam_role, ttl_minutes) -> dict|None`, `upsert_playbook(signature, action_type, bridge_service, iam_role, incident_id, simulation_id)`, `recall(cve_id=None, package_name=None) -> {playbooks, episodes}`, `finish_episode(episode_id, outcome, summary)`, `memory_overview()`.
Indexes: RANGE on `Episode.id`, `Episode.incident_id`, `Simulation.id`, `Simulation.incident_id`, `Playbook.signature`.

---

## 4. MCP tool contract (`tools.py` functions == MCP tool names)

Every function: keyword args with the exact names below, returns a JSON-serialisable `dict` that always includes
`"cypher": [...]` and `"duration_ms": float`. Errors raise `ToolError(message)` (define in tools.py); the MCP
server converts exceptions into `is_error` results. Node references in results use **names** (`service.name`,
`role.name`, `db.name`, `cve id`) so the LLM can chain calls, plus `path` objects (`{nodes:[{id,labels,name,properties}], edges:[{id,type,src_id,dst_id,properties}]}`) for the UI.

1. `find_entry_points(alert_text: str, top_k: int = 3)` — hybrid anchor. Embed `alert_text` (embeddings.embed), run vector KNN on `Vulnerability.embedding` (k=top_k) AND full-text `queryNodes('Vulnerability', <keywords>)` (keywords = alert tokens ≥4 chars joined with spaces; wrap in try/except — an empty/garbage query may raise), merge by cve id with `combined_score = fulltext_rank_bonus + (1 - vector_distance)`, then for each candidate expand `(v)-[:AFFECTS]->(p)<-[:IMPORTS]-(f)<-[:CALLS*0..3]-(entry)<-[:DEPLOYS_CODE]-(svc)` returning distinct packages and services. Returns `{"matches": [{cve_id, severity, cvss, summary, vector_distance, fulltext_score, combined_score, affected_packages:[{name, version, fixed_version}], entry_services:[str], entry_functions:[str]}], "best_cve_id": str|None, "cypher": [...], "duration_ms"}` sorted by combined_score desc.
2. `trace_blast_radius(cve_id: str, max_route_hops: int = 3)` — the 5-hop exposure query (§3.1 definition, `ROUTES_TO*0..max_route_hops`). Returns `{"cve_id", "origin_services":[str], "exposed_paths":[{origin_service, pivot_service, pivot_tier, iam_role, database, classification, access_mode, route_hops, total_hops, path_nodes:[str], path:{nodes,edges}}], "total_paths", "exposed_databases":[str], "pivot_services":[{name, tier, rps, path_count}], "cypher", "duration_ms"}` ordered by total_hops asc.
3. `rank_service_criticality()` — `algo.pageRank('Service','ROUTES_TO')` + `algo.betweenness({nodeLabels:['Service'],relationshipTypes:['ROUTES_TO']})` + `algo.HarmonicCentrality` if it accepts the same config (try/except, omit on failure). Returns `{"pagerank":[{service, tier, rps, score}], "betweenness":[{service, tier, rps, score}], "most_critical": str, "cypher", "duration_ms"}` (lists sorted desc, scores rounded to 6 dp).
4. `shortest_attack_path(source_service: str, target_database: str, max_len: int = 6)` — `algo.SPpaths` over `ROUTES_TO, ASSUMES_ROLE, CAN_ACCESS`. Returns `{"found": bool, "path_nodes":[str], "hop_count": int, "path": {...}|None, "cypher", "duration_ms"}`.
5. `expand_neighborhood(service_name: str, depth: int = 3)` — `algo.BFS(src, depth, 'ROUTES_TO')`. Returns `{"source", "depth", "reachable_services":[{name, tier, status}], "blast_radius_size": int, "edges":[{src,dst,type}], "cypher", "duration_ms"}`.
6. `detect_service_communities()` — `algo.labelPropagation` on Service/ROUTES_TO + `algo.WCC`. Returns `{"communities":[{community_id, services:[str]}], "components":[{component_id, services:[str]}], "cypher", "duration_ms"}`.
7. `find_code_owner(cve_id: str)` — kit query §4 (MAINTAINED traversal, on_call first, expertise score). Returns `{"owners":[{name, handle, team, on_call, target_file, repo_name, function, package, current_version, fixed_version, expertise_score}], "recommended": {...}|None, "cypher", "duration_ms"}`.
8. `recall_similar_incidents(cve_id: str | None = None, package_name: str | None = None)` — prod graph: past `Incident {status:'MITIGATED'}-[:RESOLVED_BY]->(ActionAudit)` filtered to the same CVE or same package (via AFFECTS) or, if neither given, latest 5; memory graph: `memory.recall(...)`. Returns `{"past_incidents":[{incident_id, title, cve_id, action_type, bridge_service, iam_role, assigned_developer, sim_passed, timestamp, rolled_back}], "playbooks":[...], "episodes":[...], "cypher", "duration_ms"}`.
9. `simulate_remediation(incident_id: str, cve_id: str, bridge_service: str, iam_role: str)` — counterfactual sandbox:
   a. refuse (`ToolError`) if `bridge_service` has `tier = 'critical'` (never isolate a critical-tier service) or does not exist;
   b. `copy_graph(prod, sim_graph_name(incident_id))`;
   c. in the sandbox: `exposure_before` = count of exposure paths for `cve_id`; DELETE every `ROUTES_TO` edge whose src OR dst is `bridge_service`; DELETE every `CAN_ACCESS` edge from `iam_role`; `exposure_after` = recount;
   d. critical flows (hard-coded list): `api-edge-gateway→auth-token-service`, `api-edge-gateway→checkout-gateway`, `checkout-gateway→payment-orchestrator`, `checkout-gateway→inventory-service` — each checked with `MATCH p=(a)-[:ROUTES_TO*1..4]->(b) RETURN count(p) > 0`;
   e. `algo.WCC` on the sandbox Service/ROUTES_TO → components; `critical_services_connected` = all `tier='critical'` services in the same component;
   f. `safe_to_execute = exposure_closed AND critical_flows_intact AND critical_services_connected`;
   g. record a `Simulation` in the memory graph; keep or delete the sandbox per `settings.keep_sandbox`.
   Returns `{"simulation_id", "sandbox_graph", "safe_to_execute", "exposure_before", "exposure_after", "exposure_closed", "critical_flows":[{source, target, intact}], "critical_flows_intact", "wcc_components":[{component_id, services}], "critical_services_connected", "severed_routes":[{src,dst}], "quarantined_access":[{role, database}], "sandbox_kept": bool, "cypher", "duration_ms"}`.
10. `execute_remediation(incident_id: str, cve_id: str, bridge_service: str, iam_role: str, justification: str)` — guarded closed-loop action:
    a. refuse unless `memory.latest_passing_simulation(incident_id, bridge_service, iam_role, settings.sim_ttl_minutes)` exists → `{"status":"REFUSED","reason":...}` (not an exception, so the LLM can recover by simulating first); refuse if bridge is critical-tier;
    b. prod mutations: `MATCH (s:Service)-[r:ROUTES_TO]->(b:Service {name:$bridge}) WHERE coalesce(r.status,'ACTIVE')='ACTIVE' SET r.status='ISOLATED_BY_AEGIS', r.previous_status='ACTIVE'` (inbound) and same for outbound edges; `SET b.status='ISOLATED'`; `MATCH (role:IAMRole {name:$role})-[acc:CAN_ACCESS]->(d) WHERE coalesce(acc.status,'ACTIVE')='ACTIVE' SET acc.status='QUARANTINED_BY_AEGIS', acc.previous_status='ACTIVE'`; `SET role.status='QUARANTINED'`;
    c. owner = `find_code_owner(cve_id)["recommended"]`; `pr_draft = {title: "fix(deps): bump <package> <current> -> <fixed> (<cve>)", branch: "aegis/<cve-lower>", assignee: handle, file: target_file, body: markdown}`; `pr_url` = `pending://github/<repo>/pull/aegis-<cve>` (clearly labelled a draft; no external call);
    d. betweenness/pagerank of the bridge from `rank_service_criticality()`;
    e. create `ActionAudit` (all §3.1 properties; `cypher_proof` = JSON of the cypher traces from this call; `proof_paths` = JSON of `trace_blast_radius` paths before action; `mutations` = JSON list of `{kind:'edge'|'node', type, src, dst, name, property, previous, new}`), `MERGE (inc)-[:RESOLVED_BY {execution_time_ms}]->(audit)`, `MODIFIED_ENTITY` to the role (ACTIVE→QUARANTINED) and bridge service (HEALTHY→ISOLATED), `SET inc.status='MITIGATED'`;
    f. verification: re-run exposure count for `cve_id` → `exposed_paths_after`; upsert `Playbook` (signature `package:<pkg>`); return `{"status":"ACTION_EXECUTED", "audit_id", "incident_status", "isolated_bridge", "quarantined_role", "mutations":[...], "assigned_code_owner":{...}, "pr_draft":{...}, "pr_url", "verification":{"exposed_paths_before","exposed_paths_after"}, "scores":{"betweenness","pagerank"}, "cypher", "duration_ms"}`.
11. `rollback_remediation(audit_id: str)` — restore every mutation recorded on the audit (edges back to `previous`, node statuses back), `SET audit.rolled_back=true`, incident back to `OPEN` if no other non-rolled-back audit. Returns `{"status":"ROLLED_BACK","restored":[...], "incident_status", "cypher", "duration_ms"}`.
12. `get_decision_proof(incident_id: str)` — incident + its audits (parsed JSON fields) + proof subgraph (nodes/edges of the proof paths + audit + incident + modified entities). Returns `{"incident":{...}, "audits":[...], "proof_subgraph":{nodes, edges}, "cypher", "duration_ms"}`.
13. `read_graph(cypher: str, limit: int = 50)` — ad-hoc **read-only** exploration via `graph.ro_query` (server rejects writes); append ` LIMIT <limit>` if the query has no LIMIT; returns `{"columns":[...], "rows":[[...]], "row_count", "cypher", "duration_ms"}`; errors → `ToolError(str(exc))`.

Also non-tool helpers in tools.py: `graph_overview()` (`{"graphs":[{name, nodes, edges, kind:'prod'|'memory'|'sandbox'}], "label_counts": {...}}`) and `list_incidents()`.

Deterministic bridge selection (`agent.rank_candidates`, also described to the LLM in the system prompt): candidates = pivot services on exposed paths; `coverage` = number of exposed paths passing through the service anywhere; critical-tier candidates are ineligible; eligible candidates are ranked by coverage (desc), then betweenness (desc), then rps (asc); role = the IAM role the chosen service assumes on the exposed paths (most paths first). The full candidate table is attached to the `decision` event. If no candidate is eligible → `NO_ACTION` outcome with explanation (never isolate critical services).

---

## 5. Agent orchestrator contract (`agent.py`)

`class AgentRunner` with `async def run(incident_id: str, alert_text: str | None, mode: Literal["auto","llm","deterministic"]) -> AsyncIterator[Event]`. `mode="auto"` → `llm` if `settings.llm_configured` else `deterministic`. Both modes call tools **only through the MCP client** (`mcp_client.MCPToolbox` which spawns `python -m aegis.mcp_server`, optionally also the official FalkorDB server, and exposes `list_tools()` + `call_tool(name, args)`); every call is recorded in memory via `memory.record_tool_call`. Each event is a dict `{"type": ..., "ts": float, "run_id": str, ...}`:

| type | fields |
|---|---|
| `run_started` | `incident_id`, `mode`, `model` (or null), `tools` (names available via MCP) |
| `stage` | `stage` (1-5), `name` (`anchor`, `blast_radius`, `chokepoint`, `simulate`, `act`), `status` (`started`/`completed`/`skipped`), `detail` |
| `thinking` | `text` (LLM thinking summary chunk) |
| `assistant_text` | `text` (narrative chunk) |
| `tool_call` | `call_id`, `name`, `args`, `seq` |
| `tool_result` | `call_id`, `name`, `result` (dict or `{"error": str}`), `duration_ms`, `is_error` |
| `graph_highlight` | `style` (`attack`/`chokepoint`/`quarantined`/`safe`/`proof`), `nodes` (names), `edges` ([{src,dst,type}]), `label` |
| `decision` | `action`, `bridge_service`, `iam_role`, `justification`, `scores` ({betweenness, pagerank}), `sim_passed`, `code_owner`, `candidates` (see §4), `simulation`, `sandbox_graph` |
| `run_completed` | `outcome`, `summary`, `audit_id`|null, `duration_ms`, `tool_call_count`, `episode_id` |
| `error` | `message`, `recoverable` |

The orchestrator derives `graph_highlight` events from tool results (exposed paths → `attack`; chosen bridge → `chokepoint`; mutations → `quarantined`; critical flows → `safe`). Deterministic sequence: recall → find_entry_points(alert_text or incident.raw_alert) → trace_blast_radius → rank_service_criticality → pick bridge (§4) → shortest_attack_path(origin, first exposed db) → find_code_owner → simulate_remediation → (if safe) execute_remediation → trace_blast_radius again (verify 0) → completed. LLM mode: system prompt explains the 5-stage doctrine, the exposure definition, the "simulate before act" and "never isolate critical tier" rules, and asks for a final 3-5 sentence explanation citing scores; tools = all MCP tools; the loop streams thinking/text and emits tool events; the orchestrator still emits `stage` events by mapping tool names to stages and `decision` from the execute result.

---

## 6. REST + SSE API (`api.py`, FastAPI, default port 8000, CORS for `settings.cors_origins`)

| Method & path | Behaviour |
|---|---|
| `GET /api/health` | `{status:'ok'|'degraded', falkordb: bool, prod_graph, graphs:[...], label_counts, llm_configured, model, mcp_servers:[...]}` — FalkorDB unreachable → HTTP 503 (Rule 3) |
| `POST /api/seed` | body `{reset_memory?: bool}` → reseed; returns label counts |
| `GET /api/incidents` | list incidents with status, cve, audit count |
| `GET /api/incidents/{id}` | incident detail (`get_decision_proof`) |
| `GET /api/graph` | `graph.graph_snapshot(prod_graph())` |
| `GET /api/graphs` | `tools.graph_overview()` |
| `GET /api/graph/{name}` | snapshot of any graph with the configured prefix (sandbox inspection) |
| `GET /api/tools` | MCP tool list `[{name, description, input_schema, server}]` |
| `POST /api/tools/{name}` | body = args → direct MCP call (manual mode in the UI) |
| `POST /api/runs` | body `{incident_id, alert_text?, mode?}` → `{run_id}`; runs the agent as an asyncio task, buffering events |
| `GET /api/runs/{run_id}` | `{run_id, status:'running'|'completed'|'error', events:[...]}` |
| `GET /api/runs/{run_id}/events` | SSE: replays buffered events then streams live; each message `event: <type>\ndata: <json>\n\n`; ends with `event: done` |
| `GET /api/memory` | `memory.memory_overview()` |
| `POST /api/rollback/{audit_id}` | `rollback_remediation` |

Sync endpoints that touch FalkorDB directly are plain `def` (FastAPI threadpool); agent runs are async. One `MCPToolbox` is created at startup (lifespan) and reused; if the MCP subprocess dies, recreate it lazily.

---

## 7. Frontend spec (`frontend/`, Vite + React 19 + TypeScript, plain CSS, `react-force-graph-2d`)

Dev server on 5173 proxies `/api` → `http://127.0.0.1:8000` (override with `AEGIS_API_URL`). Layout:
- Header: product name, health pill (FalkorDB ok / LLM mode), graph counts, link to FalkorDB Browser `http://localhost:3000`, reseed button.
- Left panel "Incidents & Run": incident list (status badges), mode selector (auto / deterministic / llm — llm disabled when `llm_configured=false` with a hint), alert text box prefilled with `raw_alert`, "Investigate & Remediate" button, 5-stage stepper driven by `stage` events, and the live MCP tool trace (expandable rows: name, args, duration, result JSON, Cypher used).
- Centre: force graph of `/api/graph`. Node colour by label (legend), size by rps for services; edge style by status (ACTIVE thin grey; `ISOLATED_BY_AEGIS`/`QUARANTINED_BY_AEGIS` dashed green); `graph_highlight` events animate `attack` edges red, `chokepoint` nodes amber ring, `quarantined` green, `safe` blue. Click a node → side details. Refetch graph after `tool_result` of `execute_remediation`/`rollback_remediation`.
- Right panel "Decision Proof": thinking/narrative stream, decision card (bridge, role, betweenness/pagerank table, sandbox result with exposure before/after and critical flows table, WCC components), code owner + PR draft, audit id, rollback button, and a "Sandbox graph" link that loads `/api/graph/<sandbox>` into the viewer.
- Memory tab: episodes/playbooks from `/api/memory`.
`npm run build` must pass with zero TypeScript errors. `?mock=1` replays `frontend/public/mock-fixture.json`, a real session recorded from the live API by `scripts/record_mock_fixture.py`. Include an `src/api.ts` typed client and `src/events.ts` types mirroring §5.

---

## 8. Testing & verification rules

- Tests in `backend/tests`, run from `backend/` with `../.venv/Scripts/python.exe -m pytest -q`. `conftest.py` sets `AEGIS_GRAPH_PREFIX=test_aegis_` and `AEGIS_KEEP_SANDBOX=false` **before** importing `aegis`, and provides a session fixture that reseeds. Never touch `aegis_*` graphs in tests.
- Required tests: seed counts/indexes; every tool (incl. the §3.2 expected facts); simulate → execute → verify 0 → rollback → verify 6; guardrails (execute without simulation is REFUSED; critical bridge refused); memory recall; MCP server (spawn via stdio, list 13 tools, call one); deterministic agent run end-to-end (events contain `decision` and `run_completed` with `audit_id`); API (`/api/health`, `/api/tools`, `/api/runs` + polling `/api/runs/{id}` until completed).
- The CLI `python -m aegis seed && python -m aegis run INC-2026-091 --mode deterministic` must work from `backend/`.
- LLM mode is covered by `tests/test_llm_loop.py`, which replaces `anthropic.AsyncAnthropic` with a scripted model (doctrine run through real MCP tools, parallel tool calls, max_tokens truncation, refusal, fallback sanitisation). A live check needs `ANTHROPIC_API_KEY`.
- Current suite: 68 tests, all green against FalkorDB 6.0.2.
