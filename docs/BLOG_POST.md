# Look before you leap: building an incident agent that proves its fix in a sandbox graph

*Draft for the Graph Hacks blog-post prize. Add your own screenshots from the console and the FalkorDB Browser.*

Most agent demos stop at an answer. Ours had to take an action in production, the kind of action that pages people at 3 a.m. if it is wrong. Building AegisGraph for Graph Hacks (WeMakeDevs x FalkorDB, Track 01) taught us that an agent's ability to act safely depends almost entirely on the shape of its context. Text chunks were not enough. A graph was.

## The question an incident actually asks

A WAF alert says forged bearer tokens are being accepted by `auth-token-service`, and points at `jwt-crypto-core`. The on-call engineer needs answers to three things at once:

1. What customer data can an attacker reach from here?
2. What can we cut to stop it without taking checkout down?
3. Who should fix the code?

Each answer lives in a different system. Package imports live in the repositories. Service-to-service traffic lives in the mesh. Data access lives in cloud IAM. The real answer is a **path** across all three: CVE → package → function → service → (more services) → IAM role → database. In our demo topology that is five to eight hops, and there are six such paths.

A vector store finds text that sounds like JWT bugs. It cannot tell you that `legacy-billing-bridge` sits on all six paths.

## One graph for code, runtime and identity

We modelled the three layers as one FalkorDB property graph:

- **Code:** `(:Vulnerability)-[:AFFECTS]->(:Package)<-[:IMPORTS]-(:Function)<-[:MAINTAINED]-(:Developer)`, plus `(:Function)-[:CALLS]->(:Function)`
- **Runtime:** `(:Service)-[:DEPLOYS_CODE]->(:Function)` and `(:Service)-[:ROUTES_TO]->(:Service)`
- **Identity and data:** `(:Service)-[:ASSUMES_ROLE]->(:IAMRole)-[:CAN_ACCESS]->(:Database)`

The whole blast radius then becomes one Cypher query:

```cypher
MATCH (v:Vulnerability {id: $cve_id})-[:AFFECTS]->(:Package)<-[:IMPORTS]-(:Function)<-[:DEPLOYS_CODE]-(origin:Service)
WITH DISTINCT origin
MATCH attack = (origin)-[:ROUTES_TO*0..3]->(pivot:Service)-[:ASSUMES_ROLE]->(role:IAMRole)
               -[:CAN_ACCESS]->(db:Database {contains_pii: true})
WHERE ALL(r IN relationships(attack) WHERE coalesce(r.status, 'ACTIVE') = 'ACTIVE')
RETURN pivot.name, role.name, db.name, [n IN nodes(attack) | n.name] AS path
```

The `status` predicate matters. Remediation never deletes production edges. It flips their status, so the same query tells you whether an attack path is still live, and rollback is a status flip back.

## Graph algorithms as tools, not decoration

Picking what to isolate is where agents usually guess. We exposed FalkorDB's built-in algorithms as MCP tools instead:

- `algo.betweenness` over `ROUTES_TO` finds where shortest paths funnel. `legacy-billing-bridge` scores 6.0, the highest of the ten services.
- `algo.pageRank` shows how much of the mesh depends on each service. It is useful context, but on a call graph it favours sinks such as telemetry, so it is not our selector.
- `algo.SPpaths` gives the exact proof path, and `algo.BFS` sizes the neighbourhood.

The runner-up by betweenness is `payment-orchestrator` at 5.83, a critical-tier service handling 3,100 requests a second. The policy is simple and lives in the tools, not just in a prompt. Rank the pivot services on the exposure paths by how many paths they cover, then by betweenness, then by lowest traffic. Never isolate a critical-tier service. The bridge wins: 6 of 6 paths, 180 rps, standard tier.

## The counterfactual sandbox

This is the part we are proudest of. Before acting, the agent calls `simulate_remediation`:

1. `GRAPH.COPY aegis_prod_graph aegis_sim_INC-2026-091` clones production, indexes included, as a separate graph in the same FalkorDB instance.
2. In the clone, it deletes every `ROUTES_TO` edge touching the bridge and every `CAN_ACCESS` edge of its admin role. Algorithms can't filter edges by property, so the sandbox models a cut as a real deletion.
3. It recounts exposure paths: six become zero.
4. It checks the four critical customer flows, such as edge → checkout and checkout → payment, with variable-length path matches. All are intact.
5. It runs `algo.WCC`. Every critical service is still in one component, and the bridge is now an island of its own.

Only a passing simulation unlocks `execute_remediation`, and the memory graph enforces that rather than the prompt. The action writes an `ActionAudit` node holding:

- the justification;
- the betweenness and PageRank scores;
- the six proof paths;
- every mutation, which is what makes one-click rollback possible;
- the exact Cypher that was executed.

The pull request goes to `@aarav-sec`, found by walking `MAINTAINED` from the vulnerable function.

## Memory that survives the session

A second graph, `aegis_memory_graph`, stores each run as an `Episode` with its ordered `ToolCall`s, every `Simulation`, and `Playbook`s keyed by package. The next time `jwt-crypto-core` shows up, the anchor stage recalls the playbook from a previous session. That happens whether the earlier run came from the CLI, the console, or Claude choosing the tools in LLM mode.

## MCP all the way down

The agent never imports its own tool functions. It spawns an MCP server over stdio, lists the 13 tools and calls them. That kept us honest: the deterministic doctrine and the Claude-driven loop use exactly the same tools, the same guardrails and the same audit trail. The server also plugs straight into Claude Desktop, and the official FalkorDB MCP server can run alongside it.

## What we learned

- **Put the safety rules in the tools.** A prompt saying "simulate first" is a suggestion. A tool that refuses to act without a recorded passing simulation is a guarantee.
- **Make every result carry its own proof.** Each tool returns the Cypher it ran with server timings. Our query documentation is generated from those traces, so it can't drift from the code.
- **Multi-graph is a feature, not a detail.** Production, memory and per-incident sandboxes in one FalkorDB instance made "look before you leap" one command.

The code, the graph model and every query are in the repository: [https://github.com/Hellinferno/graph-hack-](https://github.com/Hellinferno/graph-hack-).
