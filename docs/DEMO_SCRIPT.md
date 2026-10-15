# Demo video script (3 minutes)

Every number below comes from the seeded demo and is checked by the test suite. If you change the dataset, re-run the agent and update the numbers.

## Before recording

1. `docker compose up -d`, then `python -m aegis api` from `backend/`, then `npm run dev` in `frontend/`.
2. Reset the demo: click **Reseed graph** in the console, or run `python -m aegis seed`. The memory graph is kept, so the agent will recall the playbook it learned in an earlier session. To show a first-ever run, reset memory too: `python -m aegis seed --reset-memory`.
3. Open two tabs: the console at `http://localhost:5173` and the FalkorDB Browser at `http://localhost:3000`, connected to `aegis_prod_graph`.

## Script

| Time | On screen | Narration |
|---|---|---|
| 0:00-0:20 | Console, idle graph | "Agents that act in production need more than retrieved text. They need to know what is connected to what. AegisGraph is an incident agent whose entire context is a FalkorDB graph: code, services, IAM roles, databases, people and its own memory. Every step it takes is an MCP tool call, and every result carries the Cypher that produced it." |
| 0:20-0:45 | Select `INC-2026-091` and show the alert text. Click **Investigate & remediate**. The Anchor stage lights up. | "A WAF alert arrives as plain text: forged bearer tokens accepted by auth-token-service. The agent recalls past incidents from its memory graph. It then anchors the alert with FalkorDB's vector and full-text indexes and lands on CVE-2026-8841 in jwt-crypto-core." |
| 0:45-1:10 | Red attack paths appear. Point at the **Exposure paths** list. | "One multi-hop Cypher traversal goes from the CVE to the package, the functions that import it, the services that deploy them, the service mesh, the IAM roles and finally the PII databases. It finds six active attack paths into three databases holding customer data. All six run through one service: legacy-billing-bridge." |
| 1:10-1:40 | The amber chokepoint ring appears. Scroll to **Candidate chokepoints** and **Service centrality**. | "Which service should the agent cut? It doesn't guess. It calls FalkorDB's betweenness and PageRank algorithms through MCP. legacy-billing-bridge has the highest betweenness of all ten services. The runner-up, payment-orchestrator, is a critical-tier service handling 3,100 requests a second, so the agent protects it. The bridge is standard-tier at 180 rps and covers all six paths." |
| 1:40-2:15 | **Sandbox rehearsal** card: exposure 6 → 0, four intact flows, WCC components. Click **View sandbox graph**. | "Before touching production, it clones the graph with GRAPH.COPY into a sandbox and severs the bridge there. Then it proves three things: exposure drops from six to zero, all four critical customer flows still have a route, and weakly connected components show every critical service still in one piece. In the sandbox you can see the bridge cut off as its own island." |
| 2:15-2:40 | **Back to production graph**. Dashed green quarantined edges. **Action taken** and **Code owner and PR draft** cards. | "Only then does it act. It flags the bridge's routes and the admin role's database access as quarantined; nothing is deleted. It routes a pull request bumping jwt-crypto-core to 2.4.2 to the on-call engineer who maintains the vulnerable function, found through the graph. It writes an audit node with the scores, the proof paths and the exact Cypher. Then it re-traces: exposure zero." |
| 2:40-3:00 | Expand a tool-trace row to show its Cypher. Switch to the FalkorDB Browser and show the `ActionAudit` node linked to the incident. Click **Roll back this action**. | "Every decision is traceable to queries you can re-run, every action is reversible, and the agent remembers what worked for next time. Take FalkorDB away and AegisGraph cannot do anything, because the graph is the agent's context." |

## Judge Q&A

**Why FalkorDB and not Postgres or a vector store?**
The core question is a path of five to eight hops across code, runtime and identity. In Cypher it is one traversal with a variable-length `ROUTES_TO*0..3` segment. The decision needs betweenness, PageRank, shortest paths and connected components, which FalkorDB runs as built-in procedures inside the same query engine. The safety check needs a throwaway copy of the whole graph: `GRAPH.COPY` makes one in milliseconds, and multi-graph support keeps production, memory and sandboxes in one instance. Vector search is used only to find the starting node.

**Why betweenness and not PageRank to pick the target?**
Betweenness counts how many shortest paths pass through a service, so it finds where lateral movement funnels. PageRank over `ROUTES_TO` measures how many services depend on one. Sinks such as telemetry score high there, so it is reported as context rather than used as the selector. The selector ranks eligible pivots by how many exposure paths they cover, then by betweenness, then by lowest traffic. Tier and the sandbox proof decide safety.

**How do you know the action is safe?**
`simulate_remediation` applies the change to a `GRAPH.COPY` sandbox. It requires these things before reporting `safe_to_execute`: the CVE had exposure and none is left, each of the four critical flows keeps a route, a single WCC component holds every critical service, and the quarantined role is not shared with a critical service. `execute_remediation` refuses unless a passing simulation for the same incident, CVE, bridge and role exists in the memory graph from the last 30 minutes. After acting, it re-counts exposure on the live graph and only then marks the incident mitigated. Critical-tier services are refused outright.

**What does the LLM add, and what happens without it?**
In LLM mode, Claude gets the 13 MCP tools and the doctrine and chooses the calls itself, streaming its reasoning summaries. Without a key, the same doctrine runs deterministically over the same MCP tools. The guardrails live in the tools, so they hold in both modes.

**Is the MCP layer real or decorative?**
The agent process never imports the tool functions. It spawns the MCP server over stdio, discovers the tools with `tools/list` and calls them with `tools/call`. The same server works from Claude Desktop, and the official FalkorDB MCP server can be attached alongside it.

**What persists between sessions?**
`aegis_memory_graph` keeps every run as an `Episode` with its ordered `ToolCall`s, every `Simulation`, and `Playbook`s keyed by package. A new incident on `jwt-crypto-core` recalls the playbook from a previous session during the anchor stage.
