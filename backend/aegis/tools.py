"""Graph tools: every decision primitive the agent can call, implemented as plain functions over FalkorDB.

``mcp_server.py`` exposes these over the Model Context Protocol; ``agent.py`` only ever calls them through
MCP. Every tool returns a JSON-serialisable dict that carries ``cypher`` (the exact queries executed, with
timings) and ``duration_ms`` so each decision is explainable and auditable. Docstrings double as MCP tool
descriptions, so they say WHEN the agent should call the tool.

Exposure definition used throughout (docs/DESIGN.md §3.1): an active attack path
``(origin:Service)-[:ROUTES_TO*0..N]->(pivot:Service)-[:ASSUMES_ROLE]->(:IAMRole)-[:CAN_ACCESS]->(:Database {contains_pii: true})``
where ``origin`` deploys a function importing a package affected by the CVE, and every relationship on the
path has ``coalesce(status, 'ACTIVE') = 'ACTIVE'``.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from typing import Any, Callable

from mcp.server.mcpserver.exceptions import ToolError as MCPToolError
from redis.exceptions import ResponseError

from . import graph as g
from . import memory
from .config import settings
from .embeddings import embed, keywords
from .seed import CRITICAL_FLOWS

log = logging.getLogger("aegis.tools")


class ToolError(MCPToolError):
    """Raised for invalid input or impossible operations.

    Subclasses the MCP SDK's ToolError: the MCP server returns its message to the agent as an `is_error`
    result (so the model can recover), whereas any other exception is treated as a crash and its text is
    withheld from the client."""


class _Timer:
    def __enter__(self) -> "_Timer":
        self._t0 = time.perf_counter()
        self.ms = 0.0
        return self

    def __exit__(self, *exc: object) -> None:
        self.ms = (time.perf_counter() - self._t0) * 1000.0

    @property
    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self._t0) * 1000.0


def _finish(result: dict[str, Any], trace: list[g.CypherTrace], timer: _Timer) -> dict[str, Any]:
    result["cypher"] = [t.as_dict() for t in trace]
    result["duration_ms"] = round(timer.ms, 2)
    return result


def _check_hops(hops: int) -> int:
    if not isinstance(hops, int) or hops < 0 or hops > 6:
        raise ToolError("max_route_hops must be an integer between 0 and 6")
    return hops


EXPOSURE_MATCH = """
MATCH (v:Vulnerability {id: $cve_id})-[:AFFECTS]->(pkg:Package)<-[:IMPORTS]-(f:Function)<-[:DEPLOYS_CODE]-(origin:Service)
WITH DISTINCT origin
MATCH attack = (origin)-[:ROUTES_TO*0..{hops}]->(pivot:Service)-[:ASSUMES_ROLE]->(role:IAMRole)-[acc:CAN_ACCESS]->(db:Database {contains_pii: true})
WHERE ALL(r IN relationships(attack) WHERE coalesce(r.status, 'ACTIVE') = 'ACTIVE')
"""

EXPOSURE_RETURN = """
RETURN origin.name AS origin_service, pivot.name AS pivot_service, pivot.tier AS pivot_tier, pivot.rps AS pivot_rps,
       role.name AS iam_role, db.name AS database, db.classification AS classification, acc.access_mode AS access_mode,
       length(attack) - 2 AS route_hops, length(attack) AS total_hops,
       [n IN nodes(attack) | coalesce(n.name, n.id)] AS path_nodes, attack
ORDER BY total_hops ASC, pivot_service, database
"""


def _exposure_paths(graph, cve_id: str, hops: int, trace: list[g.CypherTrace]) -> list[dict[str, Any]]:
    rows = g.run_query(graph, EXPOSURE_MATCH.replace("{hops}", str(hops)) + EXPOSURE_RETURN, {"cve_id": cve_id}, read_only=True, trace=trace)
    return [
        {
            "origin_service": r[0], "pivot_service": r[1], "pivot_tier": r[2], "pivot_rps": r[3], "iam_role": r[4],
            "database": r[5], "classification": r[6], "access_mode": r[7], "route_hops": int(r[8]), "total_hops": int(r[9]),
            "path_nodes": r[10], "path": r[11],
        }
        for r in rows
    ]


def _exposure_count(graph, cve_id: str, hops: int, trace: list[g.CypherTrace]) -> int:
    rows = g.run_query(graph, EXPOSURE_MATCH.replace("{hops}", str(hops)) + "RETURN count(attack)", {"cve_id": cve_id}, read_only=True, trace=trace)
    return int(rows[0][0]) if rows else 0


def _service(graph, name: str, trace: list[g.CypherTrace]) -> dict[str, Any]:
    rows = g.run_query(graph, "MATCH (s:Service {name: $name}) RETURN s", {"name": name}, read_only=True, trace=trace)
    if not rows:
        raise ToolError(f"unknown service '{name}'")
    return rows[0][0]["properties"]


def _cve_exists(graph, cve_id: str, trace: list[g.CypherTrace]) -> dict[str, Any]:
    rows = g.run_query(graph, "MATCH (v:Vulnerability {id: $id}) RETURN v", {"id": cve_id}, read_only=True, trace=trace)
    if not rows:
        raise ToolError(f"unknown vulnerability '{cve_id}'")
    return rows[0][0]["properties"]


# ======================================================================================
# 1. Hybrid entry-point discovery
# ======================================================================================


def find_entry_points(alert_text: str, top_k: int = 3) -> dict[str, Any]:
    """Anchor an unstructured security alert to graph nodes. Call this FIRST when you only have raw alert text
    or an incident description and do not yet know which CVE / package / service is involved.

    Runs a hybrid search on FalkorDB: HNSW vector KNN over `Vulnerability.embedding`
    (`CALL db.idx.vector.queryNodes`) plus full-text search over `Vulnerability.summary`
    (`CALL db.idx.fulltext.queryNodes`), merges the candidates, then expands each one 4 hops
    (Vulnerability -> Package <- Function <- CALLS*0..3 <- Function <- DEPLOYS_CODE <- Service) so you learn which
    packages, functions and production services are reachable from the alert. Returns matches sorted by
    combined score with `best_cve_id`; pass that id to `trace_blast_radius`.
    """
    if not alert_text or not alert_text.strip():
        raise ToolError("alert_text must not be empty")
    top_k = max(1, min(int(top_k), 10))
    graph = g.prod_graph()
    trace: list[g.CypherTrace] = []
    with _Timer() as timer:
        vec = embed(alert_text)
        knn = g.run_query(
            graph,
            "CALL db.idx.vector.queryNodes('Vulnerability', 'embedding', $k, vecf32($vec)) YIELD node, score "
            "RETURN node.id, node.severity, node.cvss, node.summary, score ORDER BY score ASC",
            {"k": top_k, "vec": vec}, read_only=True, trace=trace,
        )
        candidates: dict[str, dict[str, Any]] = {}
        for cve, severity, cvss, summary, distance in knn:
            candidates[cve] = {"cve_id": cve, "severity": severity, "cvss": cvss, "summary": summary,
                               "vector_distance": round(float(distance), 4), "fulltext_score": 0.0}
        terms = keywords(alert_text)
        if terms:
            try:
                ft = g.run_query(
                    graph,
                    "CALL db.idx.fulltext.queryNodes('Vulnerability', $q) YIELD node, score "
                    "RETURN node.id, node.severity, node.cvss, node.summary, score ORDER BY score DESC LIMIT $k",
                    {"q": "|".join(terms), "k": top_k}, read_only=True, trace=trace,
                )
            except ResponseError as exc:  # a malformed full-text query must not break anchoring
                log.warning("full-text query failed: %s", exc)
                ft = []
            for cve, severity, cvss, summary, score in ft:
                entry = candidates.setdefault(cve, {"cve_id": cve, "severity": severity, "cvss": cvss, "summary": summary,
                                                    "vector_distance": None, "fulltext_score": 0.0})
                entry["fulltext_score"] = round(float(score), 4)
        matches = []
        for entry in candidates.values():
            vd = entry["vector_distance"]
            similarity = (1.0 - vd) if vd is not None else 0.0
            entry["combined_score"] = round(similarity + 0.1 * entry["fulltext_score"], 4)
            exp = g.run_query(
                graph,
                "MATCH (v:Vulnerability {id: $cve})-[:AFFECTS]->(p:Package) "
                "OPTIONAL MATCH (p)<-[:IMPORTS]-(f:Function)<-[:CALLS*0..3]-(entry:Function)<-[:DEPLOYS_CODE]-(svc:Service) "
                "RETURN collect(DISTINCT {name: p.name, version: p.version, fixed_version: p.fixed_version}) AS packages, "
                "       collect(DISTINCT svc.name) AS services, collect(DISTINCT entry.name) AS functions",
                {"cve": entry["cve_id"]}, read_only=True, trace=trace,
            )
            packages, services, functions = (exp[0] if exp else ([], [], []))
            entry["affected_packages"] = [p for p in packages if p and p.get("name")]
            entry["entry_services"] = sorted(s for s in services if s)
            entry["entry_functions"] = sorted(fn for fn in functions if fn)
            matches.append(entry)
        matches.sort(key=lambda m: m["combined_score"], reverse=True)
    return _finish({
        "alert_text": alert_text,
        "keywords": terms,
        "matches": matches,
        "best_cve_id": matches[0]["cve_id"] if matches else None,
    }, trace, timer)


# ======================================================================================
# 2. Multi-hop blast radius
# ======================================================================================


def trace_blast_radius(cve_id: str, max_route_hops: int = 3) -> dict[str, Any]:
    """Trace the multi-hop blast radius of a CVE through code, services and cloud identity. Call this right
    after you know the CVE id (from `find_entry_points` or the incident) and again after a remediation to
    verify the exposure is gone.

    Single OpenCypher traversal across 5 hops:
    Vulnerability -AFFECTS-> Package <-IMPORTS- Function <-DEPLOYS_CODE- Service -ROUTES_TO*0..N-> Service
    -ASSUMES_ROLE-> IAMRole -CAN_ACCESS-> Database{contains_pii:true}, keeping only ACTIVE edges.
    Returns every exposed path (with pivot service, IAM role, PII database and hop counts), the distinct
    origin services, exposed databases and pivot services with path counts.
    """
    hops = _check_hops(max_route_hops)
    graph = g.prod_graph()
    trace: list[g.CypherTrace] = []
    with _Timer() as timer:
        _cve_exists(graph, cve_id, trace)
        origins = g.run_query(
            graph,
            "MATCH (v:Vulnerability {id: $cve_id})-[:AFFECTS]->(p:Package)<-[:IMPORTS]-(f:Function)<-[:DEPLOYS_CODE]-(s:Service) "
            "RETURN DISTINCT s.name ORDER BY s.name",
            {"cve_id": cve_id}, read_only=True, trace=trace,
        )
        paths = _exposure_paths(graph, cve_id, hops, trace)
        pivots: dict[str, dict[str, Any]] = {}
        for p in paths:
            entry = pivots.setdefault(p["pivot_service"], {"name": p["pivot_service"], "tier": p["pivot_tier"],
                                                           "rps": p["pivot_rps"], "path_count": 0, "iam_roles": []})
            entry["path_count"] += 1
            if p["iam_role"] not in entry["iam_roles"]:
                entry["iam_roles"].append(p["iam_role"])
    return _finish({
        "cve_id": cve_id,
        "max_route_hops": hops,
        "origin_services": [r[0] for r in origins],
        "exposed_paths": paths,
        "total_paths": len(paths),
        "exposed_databases": sorted({p["database"] for p in paths}),
        "pivot_services": sorted(pivots.values(), key=lambda x: (-x["path_count"], x["name"])),
    }, trace, timer)


# ======================================================================================
# 3. Graph algorithms as decision primitives
# ======================================================================================


def rank_service_criticality() -> dict[str, Any]:
    """Score every production service with FalkorDB's native graph algorithms so you can choose a remediation
    target mathematically instead of guessing. Call this before deciding which service to isolate.

    `CALL algo.pageRank('Service','ROUTES_TO')` = how architecturally critical a service is (high = too
    important to take offline); `CALL algo.betweenness({nodeLabels:['Service'], relationshipTypes:['ROUTES_TO']})`
    = how many shortest paths funnel through it (high = a lateral-movement chokepoint). Harmonic centrality is
    included when available. Never isolate a `tier: critical` service; prefer the non-critical pivot with the
    highest betweenness.
    """
    graph = g.prod_graph()
    trace: list[g.CypherTrace] = []
    with _Timer() as timer:
        pr = g.run_query(
            graph,
            "CALL algo.pageRank('Service', 'ROUTES_TO') YIELD node, score "
            "RETURN node.name, node.tier, node.rps, score ORDER BY score DESC",
            read_only=True, trace=trace,
        )
        bw = g.run_query(
            graph,
            "CALL algo.betweenness({nodeLabels: ['Service'], relationshipTypes: ['ROUTES_TO']}) YIELD node, score "
            "RETURN node.name, node.tier, node.rps, score ORDER BY score DESC",
            read_only=True, trace=trace,
        )
        harmonic: list[dict[str, Any]] = []
        try:
            hc = g.run_query(
                graph,
                "CALL algo.HarmonicCentrality({nodeLabels: ['Service'], relationshipTypes: ['ROUTES_TO']}) YIELD node, score "
                "RETURN node.name, node.tier, node.rps, score ORDER BY score DESC",
                read_only=True, trace=trace,
            )
            harmonic = [{"service": r[0], "tier": r[1], "rps": r[2], "score": round(float(r[3]), 6)} for r in hc]
        except ResponseError as exc:
            log.info("harmonic centrality unavailable: %s", exc)
    pagerank = [{"service": r[0], "tier": r[1], "rps": r[2], "score": round(float(r[3]), 6)} for r in pr]
    betweenness = [{"service": r[0], "tier": r[1], "rps": r[2], "score": round(float(r[3]), 6)} for r in bw]
    return _finish({
        "pagerank": pagerank,
        "betweenness": betweenness,
        "harmonic_centrality": harmonic,
        "most_critical": pagerank[0]["service"] if pagerank else None,
        "top_chokepoint": betweenness[0]["service"] if betweenness else None,
    }, trace, timer)


def shortest_attack_path(source_service: str, target_database: str, max_len: int = 6) -> dict[str, Any]:
    """Compute the exact shortest attack chain from a service to a database with FalkorDB's `algo.SPpaths`
    (relTypes ROUTES_TO, ASSUMES_ROLE, CAN_ACCESS). Use it to produce the concrete proof path for a decision
    or to check how many hops separate an entry point from a crown-jewel database. `active` tells you whether
    every edge on that path is still ACTIVE (false after a quarantine).
    """
    max_len = max(1, min(int(max_len), 10))
    graph = g.prod_graph()
    trace: list[g.CypherTrace] = []
    with _Timer() as timer:
        _service(graph, source_service, trace)
        rows = g.run_query(
            graph,
            "MATCH (src:Service {name: $src}), (dst:Database {name: $dst}) "
            "CALL algo.SPpaths({sourceNode: src, targetNode: dst, relTypes: ['ROUTES_TO', 'ASSUMES_ROLE', 'CAN_ACCESS'], maxLen: $max_len}) "
            "YIELD path, pathWeight "
            "RETURN [n IN nodes(path) | coalesce(n.name, n.id)] AS path_nodes, pathWeight, length(path), "
            "       ALL(r IN relationships(path) WHERE coalesce(r.status, 'ACTIVE') = 'ACTIVE') AS active, path",
            {"src": source_service, "dst": target_database, "max_len": max_len}, read_only=True, trace=trace,
        )
    if not rows:
        return _finish({"found": False, "source_service": source_service, "target_database": target_database,
                        "path_nodes": [], "hop_count": None, "active": None, "path": None}, trace, timer)
    r = rows[0]
    return _finish({
        "found": True, "source_service": source_service, "target_database": target_database,
        "path_nodes": r[0], "path_weight": r[1], "hop_count": int(r[2]), "active": bool(r[3]), "path": r[4],
    }, trace, timer)


def expand_neighborhood(service_name: str, depth: int = 3) -> dict[str, Any]:
    """Enumerate every service reachable from a service within N ROUTES_TO hops using FalkorDB's `algo.BFS`.
    Use it to size the lateral-movement blast radius of a compromised or candidate service before isolating it.
    """
    depth = max(1, min(int(depth), 6))
    graph = g.prod_graph()
    trace: list[g.CypherTrace] = []
    with _Timer() as timer:
        _service(graph, service_name, trace)
        rows = g.run_query(
            graph,
            "MATCH (s:Service {name: $name}) CALL algo.BFS(s, $depth, 'ROUTES_TO') YIELD nodes, edges RETURN nodes, edges",
            {"name": service_name, "depth": depth}, read_only=True, trace=trace,
        )
    nodes = rows[0][0] if rows else []
    edges = rows[0][1] if rows else []
    reachable = [{"name": n["name"], "tier": n["properties"].get("tier"), "status": n["properties"].get("status")} for n in nodes]
    id_to_name = {n["id"]: n["name"] for n in nodes}
    return _finish({
        "source": service_name,
        "depth": depth,
        "reachable_services": reachable,
        "blast_radius_size": len(reachable),
        "edges": [{"src": id_to_name.get(e["src_id"], e["src_id"]), "dst": id_to_name.get(e["dst_id"], e["dst_id"]),
                   "type": e["type"], "status": e["properties"].get("status", "ACTIVE")} for e in edges],
    }, trace, timer)


def detect_service_communities() -> dict[str, Any]:
    """Cluster the service mesh with FalkorDB's `algo.labelPropagation` (communities of tightly coupled
    services) and `algo.WCC` (weakly connected components). Use it to understand which services move together
    and to confirm the mesh is one connected system before and after a change.
    """
    graph = g.prod_graph()
    trace: list[g.CypherTrace] = []
    with _Timer() as timer:
        lp = g.run_query(
            graph,
            "CALL algo.labelPropagation({nodeLabels: ['Service'], relationshipTypes: ['ROUTES_TO']}) YIELD node, communityId "
            "RETURN communityId, collect(node.name) ORDER BY size(collect(node.name)) DESC",
            read_only=True, trace=trace,
        )
        wcc = g.run_query(
            graph,
            "CALL algo.WCC({nodeLabels: ['Service'], relationshipTypes: ['ROUTES_TO']}) YIELD node, componentId "
            "RETURN componentId, collect(node.name) ORDER BY size(collect(node.name)) DESC",
            read_only=True, trace=trace,
        )
    return _finish({
        "communities": [{"community_id": int(r[0]), "services": sorted(r[1])} for r in lp],
        "components": [{"component_id": int(r[0]), "services": sorted(r[1])} for r in wcc],
    }, trace, timer)


# ======================================================================================
# 4. Ownership + memory
# ======================================================================================


def find_code_owner(cve_id: str) -> dict[str, Any]:
    """Find the engineer who should receive the remediation pull request for a CVE by traversing
    Vulnerability -> Package <- Function <- MAINTAINED <- Developer, ranked by on-call status, commits on the
    vulnerable function and breadth of ownership. Call it before executing a remediation so the PR is routed
    to the right owner; `recommended` is the top candidate.
    """
    graph = g.prod_graph()
    trace: list[g.CypherTrace] = []
    with _Timer() as timer:
        _cve_exists(graph, cve_id, trace)
        rows = g.run_query(
            graph,
            "MATCH (v:Vulnerability {id: $cve_id})-[:AFFECTS]->(p:Package)<-[:IMPORTS]-(f:Function)<-[m:MAINTAINED]-(dev:Developer) "
            "OPTIONAL MATCH (dev)-[:MAINTAINED]->(other:Function) "
            "RETURN dev.name, dev.handle, dev.team, dev.on_call, f.file_path, f.repo_name, f.name, p.name, p.version, p.fixed_version, "
            "       m.commits_count, count(DISTINCT other) AS expertise "
            "ORDER BY dev.on_call DESC, m.commits_count DESC, expertise DESC",
            {"cve_id": cve_id}, read_only=True, trace=trace,
        )
    owners: list[dict[str, Any]] = []
    seen: set[str] = set()
    for r in rows:
        if r[1] in seen:
            continue
        seen.add(r[1])
        owners.append({
            "name": r[0], "handle": r[1], "team": r[2], "on_call": bool(r[3]), "target_file": r[4], "repo_name": r[5],
            "function": r[6], "package": r[7], "current_version": r[8], "fixed_version": r[9],
            "commits_on_function": r[10], "expertise_score": int(r[11]),
        })
    return _finish({"cve_id": cve_id, "owners": owners, "recommended": owners[0] if owners else None}, trace, timer)


def recall_similar_incidents(cve_id: str | None = None, package_name: str | None = None) -> dict[str, Any]:
    """Recall what worked before. Call this at the START of an investigation (and before choosing an action)
    to reuse proven remediation playbooks: past mitigated incidents with their audited actions from the
    production graph, plus episodes, simulations and playbooks from the agent's memory graph, filtered to the
    same CVE or package when given.
    """
    graph = g.prod_graph()
    trace: list[g.CypherTrace] = []
    with _Timer() as timer:
        rows = g.run_query(
            graph,
            "MATCH (inc:Incident {status: 'MITIGATED'})-[:RESOLVED_BY]->(a:ActionAudit) "
            "OPTIONAL MATCH (inc)-[:TRIGGERED_ON]->(v:Vulnerability) "
            "OPTIONAL MATCH (v)-[:AFFECTS]->(p:Package) "
            "RETURN inc.id, inc.title, v.id, collect(DISTINCT p.name), a "
            "ORDER BY a.timestamp DESC LIMIT 20",
            read_only=True, trace=trace,
        )
        past = []
        for inc_id, title, cve, packages, audit in rows:
            props = audit["properties"]
            past.append({
                "incident_id": inc_id, "title": title, "cve_id": cve, "packages": packages,
                "audit_id": props.get("id"), "action_type": props.get("action_type"), "bridge_service": props.get("bridge_service"),
                "iam_role": props.get("iam_role"), "assigned_developer": props.get("assigned_developer"),
                "sim_passed": props.get("sim_passed"), "timestamp": props.get("timestamp"), "rolled_back": props.get("rolled_back"),
                "justification": props.get("justification"),
            })
        if cve_id or package_name:
            filtered = [p for p in past if (cve_id and p["cve_id"] == cve_id) or (package_name and package_name in (p["packages"] or []))]
        else:
            filtered = past
        mem = memory.recall(cve_id=cve_id, package_name=package_name, trace=trace)
    return _finish({
        "cve_id": cve_id, "package_name": package_name,
        "past_incidents": filtered[:5],
        "other_recent_incidents": [p for p in past if p not in filtered][:5],
        "playbooks": mem["playbooks"],
        "episodes": mem["episodes"],
    }, trace, timer)


# ======================================================================================
# 5. Counterfactual sandbox simulation (look before you leap)
# ======================================================================================


def simulate_remediation(incident_id: str, cve_id: str, bridge_service: str, iam_role: str) -> dict[str, Any]:
    """Prove a remediation is safe BEFORE touching production. REQUIRED before `execute_remediation`.

    Clones the production graph into an isolated FalkorDB sandbox graph (`GRAPH.COPY`), severs every ROUTES_TO
    edge touching `bridge_service` and every CAN_ACCESS edge of `iam_role`, then verifies with graph queries and
    algorithms that (a) the CVE actually had exposure paths and they drop to zero, (b) the critical customer flows
    (edge->auth, edge->checkout, checkout->payment, checkout->inventory) still have a route, and (c) every
    critical-tier service stays in one weakly connected component (`CALL algo.WCC`). `iam_role` must be a role the
    bridge service assumes, and a role also assumed by a critical-tier service is never safe to quarantine.
    Refuses to simulate isolating a `tier: critical` service. Each simulation gets its own sandbox graph, whose
    name is returned so it can be inspected.
    """
    graph = g.prod_graph()
    trace: list[g.CypherTrace] = []
    with _Timer() as timer:
        _cve_exists(graph, cve_id, trace)
        svc = _service(graph, bridge_service, trace)
        if svc.get("tier") == "critical":
            raise ToolError(f"refusing to simulate isolation of critical-tier service '{bridge_service}'")
        role_rows = g.run_query(graph, "MATCH (r:IAMRole {name: $name}) RETURN r", {"name": iam_role}, read_only=True, trace=trace)
        if not role_rows:
            raise ToolError(f"unknown IAM role '{iam_role}'")
        if not _assumes_role(graph, bridge_service, iam_role, trace):
            raise ToolError(f"'{bridge_service}' does not assume IAM role '{iam_role}'; quarantine the role the bridge service uses")
        critical_users = _critical_role_users(graph, iam_role, trace)
        incident_rows = g.run_query(graph, "MATCH (i:Incident {id: $id}) RETURN i", {"id": incident_id}, read_only=True, trace=trace)
        if not incident_rows:
            raise ToolError(f"unknown incident '{incident_id}'")

        simulation_id = memory.new_id("SIM")
        # one sandbox per simulation, so concurrent simulations of the same incident never share (or delete) a graph
        sandbox = g.sim_graph_name(f"{incident_id}_{simulation_id.rsplit('-', 1)[-1]}")
        g.copy_graph(settings.prod_graph_name, sandbox)
        trace.append(g.CypherTrace(cypher=f"GRAPH.COPY {settings.prod_graph_name} {sandbox}", graph=sandbox))
        try:
            result = _run_sandbox(sandbox, simulation_id, incident_id, cve_id, bridge_service, iam_role, critical_users, trace)
        finally:
            if not settings.keep_sandbox:
                g.delete_graph_if_exists(sandbox)
        if settings.keep_sandbox:
            _prune_sandboxes(incident_id)
    return _finish(result, trace, timer)


KEEP_SANDBOXES_PER_INCIDENT = 3


def _prune_sandboxes(incident_id: str) -> None:
    """Keep only the newest sandboxes of an incident (each is a full copy of production)."""
    for name in memory.sandboxes_for_incident(incident_id, g.sim_graph_name(incident_id) + "_")[KEEP_SANDBOXES_PER_INCIDENT:]:
        g.delete_graph_if_exists(name)


def _run_sandbox(sandbox: str, simulation_id: str, incident_id: str, cve_id: str, bridge_service: str, iam_role: str,
                 critical_users: list[str], trace: list[g.CypherTrace]) -> dict[str, Any]:
    """Apply the change in the sandbox and verify exposure, critical flows and WCC; records the Simulation."""
    sim = g.get_db().select_graph(sandbox)

    # materialise existing status flags so WCC sees the live topology
    g.run_query(sim, "MATCH ()-[r]->() WHERE r.status IS NOT NULL AND r.status <> 'ACTIVE' DELETE r", trace=trace)
    before = _exposure_count(sim, cve_id, 3, trace)

    severed = g.run_query(
        sim,
        "MATCH (a:Service)-[r:ROUTES_TO]-(b:Service {name: $bridge}) "
        "RETURN DISTINCT startNode(r).name AS src, endNode(r).name AS dst",
        {"bridge": bridge_service}, read_only=True, trace=trace,
    )
    g.run_query(sim, "MATCH (a:Service)-[r:ROUTES_TO]-(b:Service {name: $bridge}) DELETE r", {"bridge": bridge_service}, trace=trace)
    quarantined = g.run_query(
        sim,
        "MATCH (role:IAMRole {name: $role})-[acc:CAN_ACCESS]->(d:Database) RETURN role.name, d.name",
        {"role": iam_role}, read_only=True, trace=trace,
    )
    g.run_query(sim, "MATCH (role:IAMRole {name: $role})-[acc:CAN_ACCESS]->(d:Database) DELETE acc", {"role": iam_role}, trace=trace)

    after = _exposure_count(sim, cve_id, 3, trace)

    flows = []
    for src, dst in CRITICAL_FLOWS:
        # FalkorDB 6 rejects path patterns inside exists(); counting matched paths is the supported form.
        rows = g.run_query(
            sim,
            "MATCH p = (a:Service {name: $src})-[:ROUTES_TO*1..4]->(b:Service {name: $dst}) RETURN count(p) > 0",
            {"src": src, "dst": dst}, read_only=True, trace=trace,
        )
        flows.append({"source": src, "target": dst, "intact": bool(rows[0][0]) if rows else False})
    flows_intact = all(f["intact"] for f in flows)

    wcc = g.run_query(
        sim,
        "CALL algo.WCC({nodeLabels: ['Service'], relationshipTypes: ['ROUTES_TO']}) YIELD node, componentId "
        "RETURN componentId, collect(node.name), collect(node.tier)",
        read_only=True, trace=trace,
    )
    components = [{"component_id": int(r[0]), "services": sorted(r[1]),
                   "critical_members": sorted(n for n, t in zip(r[1], r[2]) if t == "critical")} for r in wcc]
    critical_component_ids = {c["component_id"] for c in components if c["critical_members"]}
    connected = len(critical_component_ids) == 1

    unsafe_reasons = []
    if before == 0:
        unsafe_reasons.append(f"{cve_id} has no active exposure path, so there is nothing for this action to close")
    if after > 0:
        unsafe_reasons.append(f"{after} exposure path(s) remain after the change")
    if not flows_intact:
        unsafe_reasons.append("a critical customer flow loses its route")
    if not connected:
        unsafe_reasons.append("critical-tier services are split across components")
    if critical_users:
        unsafe_reasons.append(f"role '{iam_role}' is also assumed by critical-tier service(s) {critical_users}")
    safe = not unsafe_reasons
    result = {
        "simulation_id": simulation_id,
        "incident_id": incident_id,
        "cve_id": cve_id,
        "bridge_service": bridge_service,
        "iam_role": iam_role,
        "sandbox_graph": sandbox,
        "safe_to_execute": safe,
        "unsafe_reasons": unsafe_reasons,
        "exposure_before": before,
        "exposure_after": after,
        "exposure_closed": before > 0 and after == 0,
        "critical_flows": flows,
        "critical_flows_intact": flows_intact,
        "wcc_components": components,
        "critical_services_connected": connected,
        "role_shared_with_critical": critical_users,
        "severed_routes": [{"src": r[0], "dst": r[1]} for r in severed],
        "quarantined_access": [{"role": r[0], "database": r[1]} for r in quarantined],
        "sandbox_kept": settings.keep_sandbox,
    }
    memory.record_simulation(result, trace=trace)
    return result


def _assumes_role(graph, bridge_service: str, iam_role: str, trace: list[g.CypherTrace]) -> bool:
    rows = g.run_query(
        graph,
        "MATCH (s:Service {name: $bridge})-[:ASSUMES_ROLE]->(r:IAMRole {name: $role}) RETURN count(r) > 0",
        {"bridge": bridge_service, "role": iam_role}, read_only=True, trace=trace,
    )
    return bool(rows and rows[0][0])


def _critical_role_users(graph, iam_role: str, trace: list[g.CypherTrace]) -> list[str]:
    rows = g.run_query(
        graph,
        "MATCH (s:Service {tier: 'critical'})-[:ASSUMES_ROLE]->(r:IAMRole {name: $role}) RETURN s.name ORDER BY s.name",
        {"role": iam_role}, read_only=True, trace=trace,
    )
    return [r[0] for r in rows]


# ======================================================================================
# 6. Closed-loop action, rollback and proof
# ======================================================================================

ACTION_TYPE = "SURGICAL_BRIDGE_ISOLATION_AND_ROLE_QUARANTINE_WITH_OWNER_PR"

# Production mutations (execute / rollback) are serialised: the MCP server runs tool calls in worker threads,
# and two concurrent runs must never interleave their status flips.
_mutation_lock = threading.Lock()


def execute_remediation(incident_id: str, cve_id: str, bridge_service: str, iam_role: str, justification: str) -> dict[str, Any]:
    """Execute the verified remediation on the production graph. Only call this AFTER `simulate_remediation`
    returned `safe_to_execute: true` for the same incident, CVE, bridge service and IAM role (the tool refuses
    otherwise, returning status REFUSED rather than acting). `justification` must cite the graph evidence
    (exposed paths, betweenness/pagerank, sandbox result).

    Actions, all surgical and reversible: flags every ACTIVE ROUTES_TO edge touching the bridge service as
    ISOLATED_BY_AEGIS, flags the IAM role's CAN_ACCESS edges as QUARANTINED_BY_AEGIS, marks the service ISOLATED
    and the role QUARANTINED, routes a draft pull request (package bump) to the code owner found in the graph,
    writes an immutable `ActionAudit` node (scores, proof paths, mutations, Cypher) linked to the incident and
    to the modified entities, then re-runs the exposure query. Only when the exposure is verified to be zero is
    the incident marked MITIGATED and a playbook recorded (status ACTION_EXECUTED); otherwise the status is
    PARTIAL, the incident stays OPEN and the audit can be rolled back.
    """
    graph = g.prod_graph()
    trace: list[g.CypherTrace] = []
    with _mutation_lock, _Timer() as timer:
        _cve_exists(graph, cve_id, trace)
        svc = _service(graph, bridge_service, trace)
        if svc.get("tier") == "critical":
            return _finish({"status": "REFUSED", "reason": f"'{bridge_service}' is a critical-tier service; AegisGraph never isolates critical services"}, trace, timer)
        if svc.get("status") == "ISOLATED":
            return _finish({"status": "REFUSED", "reason": f"'{bridge_service}' is already isolated by an earlier action; roll that audit back before acting again"}, trace, timer)
        role_rows = g.run_query(graph, "MATCH (r:IAMRole {name: $name}) RETURN r", {"name": iam_role}, read_only=True, trace=trace)
        if not role_rows:
            raise ToolError(f"unknown IAM role '{iam_role}'")
        if role_rows[0][0]["properties"].get("status") == "QUARANTINED":
            return _finish({"status": "REFUSED", "reason": f"role '{iam_role}' is already quarantined by an earlier action; roll that audit back before acting again"}, trace, timer)
        if not _assumes_role(graph, bridge_service, iam_role, trace):
            return _finish({"status": "REFUSED", "reason": f"'{bridge_service}' does not assume IAM role '{iam_role}'"}, trace, timer)
        critical_users = _critical_role_users(graph, iam_role, trace)
        if critical_users:
            return _finish({"status": "REFUSED", "reason": f"role '{iam_role}' is also used by critical-tier service(s) {critical_users}; quarantining it would cut them off"}, trace, timer)
        sim = memory.latest_passing_simulation(incident_id, cve_id, bridge_service, iam_role, trace=trace)
        if not sim:
            return _finish({
                "status": "REFUSED",
                "reason": f"no passing simulation found for incident={incident_id} cve={cve_id} bridge={bridge_service} role={iam_role} "
                          f"within the last {settings.sim_ttl_minutes} minutes; call simulate_remediation first",
            }, trace, timer)
        if not justification or len(justification.strip()) < 20:
            return _finish({"status": "REFUSED", "reason": "justification must explain the decision (>= 20 characters)"}, trace, timer)
        incident_rows = g.run_query(graph, "MATCH (i:Incident {id: $id}) RETURN i", {"id": incident_id}, read_only=True, trace=trace)
        if not incident_rows:
            raise ToolError(f"unknown incident '{incident_id}'")

        before_paths = _exposure_paths(graph, cve_id, 3, trace)
        if not before_paths:
            return _finish({"status": "NO_ACTION_NEEDED",
                            "reason": f"{cve_id} has no active exposure path to a PII database; nothing to remediate"}, trace, timer)
        # Every flipped edge and node records which audit holds it (`held_by`), so an edge shared by two actions
        # is only restored when the last one is rolled back.
        audit_id = memory.new_id("AUDIT")
        mutations: list[dict[str, Any]] = []
        hold_edge = (
            "WHERE coalesce(r.status, 'ACTIVE') IN ['ACTIVE', $flag] "
            "WITH a, b, r, coalesce(r.status, 'ACTIVE') AS before "
            "SET r.previous_status = CASE WHEN before = 'ACTIVE' THEN 'ACTIVE' ELSE r.previous_status END, "
            "    r.held_by = coalesce(r.held_by, []) + [$audit_id], r.status = $flag "
            "RETURN a.name, b.name, before"
        )
        routes = g.run_query(
            graph, "MATCH (a:Service)-[r:ROUTES_TO]->(b:Service) WHERE a.name = $bridge OR b.name = $bridge " + hold_edge.replace("WHERE", "AND", 1),
            {"bridge": bridge_service, "flag": "ISOLATED_BY_AEGIS", "audit_id": audit_id}, trace=trace,
        )
        for src, dst, before in routes:
            mutations.append({"kind": "edge", "type": "ROUTES_TO", "src": src, "dst": dst, "src_label": "Service", "dst_label": "Service",
                              "property": "status", "previous": before, "new": "ISOLATED_BY_AEGIS"})
        hold_node = (
            "WITH n, coalesce(n.status, $default) AS before "
            "SET n.previous_status = CASE WHEN size(coalesce(n.held_by, [])) = 0 THEN before ELSE n.previous_status END, "
            "    n.held_by = coalesce(n.held_by, []) + [$audit_id], n.status = $flag "
            "RETURN before"
        )
        prev_svc = g.run_query(graph, "MATCH (n:Service {name: $name}) " + hold_node,
                               {"name": bridge_service, "default": "HEALTHY", "flag": "ISOLATED", "audit_id": audit_id}, trace=trace)
        bridge_prev = prev_svc[0][0] if prev_svc else "HEALTHY"
        mutations.append({"kind": "node", "label": "Service", "name": bridge_service, "property": "status", "previous": bridge_prev, "new": "ISOLATED"})

        access = g.run_query(
            graph, "MATCH (a:IAMRole {name: $role})-[r:CAN_ACCESS]->(b:Database) " + hold_edge,
            {"role": iam_role, "flag": "QUARANTINED_BY_AEGIS", "audit_id": audit_id}, trace=trace,
        )
        for src, dst, before in access:
            mutations.append({"kind": "edge", "type": "CAN_ACCESS", "src": src, "dst": dst, "src_label": "IAMRole", "dst_label": "Database",
                              "property": "status", "previous": before, "new": "QUARANTINED_BY_AEGIS"})
        prev_role = g.run_query(graph, "MATCH (n:IAMRole {name: $name}) " + hold_node,
                                {"name": iam_role, "default": "ACTIVE", "flag": "QUARANTINED", "audit_id": audit_id}, trace=trace)
        role_prev = prev_role[0][0] if prev_role else "ACTIVE"
        mutations.append({"kind": "node", "label": "IAMRole", "name": iam_role, "property": "status", "previous": role_prev, "new": "QUARANTINED"})

        owner = find_code_owner(cve_id)
        rec = owner.get("recommended") or {}
        trace.extend(g.CypherTrace(**{k: v for k, v in t.items() if k in ("cypher", "params", "run_time_ms", "graph")}, row_count=t.get("rows", 0)) for t in owner["cypher"])
        package = rec.get("package") or "unknown-package"
        pr_draft = {
            "title": f"fix(deps): bump {package} {rec.get('current_version', '?')} -> {rec.get('fixed_version', '?')} ({cve_id})",
            "branch": f"aegis/{cve_id.lower()}",
            "repo": rec.get("repo_name"),
            "file": rec.get("target_file"),
            "assignee": rec.get("handle"),
            "body": (
                f"AegisGraph detected that `{rec.get('function')}` in `{rec.get('target_file')}` imports `{package}` "
                f"{rec.get('current_version')} which is affected by {cve_id}. This PR bumps it to {rec.get('fixed_version')}.\n\n"
                f"Incident: {incident_id}. Containment already applied: `{bridge_service}` isolated, IAM role `{iam_role}` quarantined. "
                f"Blast radius before containment: {len(before_paths)} active paths to PII databases."
            ),
        }
        pr_url = f"pending://github/{rec.get('repo_name') or 'unknown'}/pull/aegis-{cve_id.lower()}"

        scores = rank_service_criticality()
        bw = next((s["score"] for s in scores["betweenness"] if s["service"] == bridge_service), 0.0)
        pr_score = next((s["score"] for s in scores["pagerank"] if s["service"] == bridge_service), 0.0)

        now = int(time.time())
        g.run_query(
            graph,
            "MATCH (inc:Incident {id: $incident_id}), (role:IAMRole {name: $role}), (b:Service {name: $bridge}) "
            "CREATE (a:ActionAudit {id: $audit_id, timestamp: $ts, action_type: $action_type, target_entity: $target, cve_id: $cve_id, "
            "  bridge_service: $bridge, iam_role: $role, betweenness_score: $bw, pagerank_score: $pr, sim_passed: true, "
            "  simulation_id: $sim_id, cypher_proof: $cypher_proof, proof_paths: $proof_paths, mutations: $mutations, "
            "  assigned_developer: $dev, pr_url: $pr_url, justification: $justification, rolled_back: false, mode: $mode}) "
            "CREATE (inc)-[:RESOLVED_BY {execution_time_ms: $exec_ms}]->(a) "
            "CREATE (a)-[:MODIFIED_ENTITY {previous_state: $role_prev, new_state: 'QUARANTINED', entity_kind: 'IAMRole'}]->(role) "
            "CREATE (a)-[:MODIFIED_ENTITY {previous_state: $bridge_prev, new_state: 'ISOLATED', entity_kind: 'Service'}]->(b) "
            "RETURN a.id",
            {
                "incident_id": incident_id, "role": iam_role, "bridge": bridge_service, "audit_id": audit_id, "ts": now,
                "action_type": ACTION_TYPE, "target": f"{iam_role} -> {', '.join(sorted({d for _, d, _ in access})) or 'n/a'}",
                "cve_id": cve_id, "bw": float(bw), "pr": float(pr_score), "sim_id": sim.get("id", ""),
                "cypher_proof": json.dumps([t.as_dict() for t in trace], default=str), "proof_paths": json.dumps(before_paths, default=str),
                "mutations": json.dumps(mutations), "dev": rec.get("handle") or "", "pr_url": pr_url,
                "justification": justification, "mode": "mcp", "exec_ms": round(timer.elapsed_ms, 2),
                "role_prev": role_prev, "bridge_prev": bridge_prev,
            },
            trace=trace,
        )
        # verify on the live graph before declaring success
        after = _exposure_count(graph, cve_id, 3, trace)
        verified = after == 0
        status_rows = g.run_query(
            graph,
            "MATCH (inc:Incident {id: $incident_id})-[:RESOLVED_BY]->(a:ActionAudit {id: $audit_id}) "
            "SET a.exposure_after = $after, inc.status = CASE WHEN $verified THEN 'MITIGATED' ELSE inc.status END "
            "RETURN inc.status",
            {"incident_id": incident_id, "audit_id": audit_id, "after": after, "verified": verified}, trace=trace,
        )
        playbook = None
        if verified:
            playbook = f"package:{package}"
            memory.upsert_playbook(playbook, ACTION_TYPE, bridge_service, iam_role, incident_id, simulation_id=sim.get("id"), trace=trace)
    result: dict[str, Any] = {
        "status": "ACTION_EXECUTED" if verified else "PARTIAL",
        "audit_id": audit_id,
        "incident_id": incident_id,
        "incident_status": status_rows[0][0] if status_rows else None,
        "isolated_bridge": bridge_service,
        "quarantined_role": iam_role,
        "mutations": mutations,
        "assigned_code_owner": rec or None,
        "pr_draft": pr_draft,
        "pr_url": pr_url,
        "verification": {"exposed_paths_before": len(before_paths), "exposed_paths_after": after},
        "scores": {"betweenness": bw, "pagerank": pr_score},
        "simulation_id": sim.get("id"),
        "playbook": playbook,
    }
    if not verified:
        result["reason"] = (f"{after} exposure path(s) for {cve_id} remain after the change, so the incident stays OPEN; "
                            f"investigate or roll back audit {audit_id}")
    return _finish(result, trace, timer)


_EDGE_TYPES = {"ROUTES_TO", "CAN_ACCESS"}
_LABELS = {"Service", "IAMRole", "Database"}


def rollback_remediation(audit_id: str) -> dict[str, Any]:
    """Undo a remediation: release this action's hold on every edge and node it changed, restoring each one's
    previous status once no other active action still holds it, mark the audit `rolled_back` and reopen the incident
    if no other action remains. Use it when an action turns out to be wrong or after a demo.
    """
    graph = g.prod_graph()
    trace: list[g.CypherTrace] = []
    with _mutation_lock, _Timer() as timer:
        rows = g.run_query(graph, "MATCH (a:ActionAudit {id: $id}) RETURN a", {"id": audit_id}, read_only=True, trace=trace)
        if not rows:
            raise ToolError(f"unknown audit '{audit_id}'")
        audit = rows[0][0]["properties"]
        if audit.get("rolled_back"):
            return _finish({"status": "ALREADY_ROLLED_BACK", "audit_id": audit_id, "restored": [], "skipped": [],
                            "incident_id": None, "incident_status": None}, trace, timer)
        try:
            mutations = json.loads(audit.get("mutations") or "[]")
        except json.JSONDecodeError as exc:
            raise ToolError(f"audit {audit_id} has unreadable mutations: {exc}") from exc
        restored, skipped = [], []
        release = (
            "WITH x, [h IN x.held_by WHERE h <> $audit_id] AS rest, coalesce(x.previous_status, $previous) AS prev "
            "SET x.held_by = CASE WHEN size(rest) = 0 THEN NULL ELSE rest END, "
            "    x.status = CASE WHEN size(rest) = 0 THEN prev ELSE x.status END, "
            "    x.previous_status = CASE WHEN size(rest) = 0 THEN NULL ELSE x.previous_status END "
            "RETURN size(rest)"
        )
        for m in reversed(mutations):
            if m.get("kind") == "edge" and m.get("type") in _EDGE_TYPES and m.get("src_label") in _LABELS and m.get("dst_label") in _LABELS:
                # labels/types are whitelisted above, so interpolating them into the pattern is safe
                rows = g.run_query(
                    graph,
                    f"MATCH (a:{m['src_label']} {{name: $src}})-[x:{m['type']}]->(b:{m['dst_label']} {{name: $dst}}) "
                    "WHERE $audit_id IN coalesce(x.held_by, []) " + release,
                    {"src": m["src"], "dst": m["dst"], "audit_id": audit_id, "previous": m.get("previous") or "ACTIVE"}, trace=trace,
                )
            elif m.get("kind") == "node" and m.get("label") in _LABELS:
                rows = g.run_query(
                    graph,
                    f"MATCH (x:{m['label']} {{name: $name}}) WHERE $audit_id IN coalesce(x.held_by, []) " + release,
                    {"name": m["name"], "audit_id": audit_id, "previous": m.get("previous")}, trace=trace,
                )
            else:
                continue
            if rows and rows[0][0] == 0:
                restored.append(m)
            else:  # still held by another active action, or no longer in the state this action left it
                skipped.append({**m, "why": "still held by another active action" if rows else "changed since this action"})
        status_rows = g.run_query(
            graph,
            "MATCH (a:ActionAudit {id: $id}) SET a.rolled_back = true, a.rolled_back_at = $ts "
            "WITH a MATCH (inc:Incident)-[:RESOLVED_BY]->(a) "
            "OPTIONAL MATCH (inc)-[:RESOLVED_BY]->(other:ActionAudit) WHERE other.id <> a.id AND coalesce(other.rolled_back, false) = false "
            "WITH inc, count(other) AS remaining "
            "SET inc.status = CASE WHEN remaining = 0 THEN 'OPEN' ELSE inc.status END "
            "RETURN inc.id, inc.status",
            {"id": audit_id, "ts": int(time.time())}, trace=trace,
        )
    return _finish({
        "status": "ROLLED_BACK",
        "audit_id": audit_id,
        "restored": restored,
        "skipped": skipped,
        "incident_id": status_rows[0][0] if status_rows else None,
        "incident_status": status_rows[0][1] if status_rows else None,
    }, trace, timer)


def get_decision_proof(incident_id: str) -> dict[str, Any]:
    """Return the explainability record for an incident: the incident, its triggering vulnerability, every
    `ActionAudit` (scores, justification, proof paths, mutations, Cypher trace, PR draft) and a proof subgraph
    (incident, audits, modified entities and the attack paths that justified the action) for visualisation.
    Call it to explain or review a past decision.
    """
    graph = g.prod_graph()
    trace: list[g.CypherTrace] = []
    with _Timer() as timer:
        rows = g.run_query(
            graph,
            "MATCH (inc:Incident {id: $id}) OPTIONAL MATCH (inc)-[:TRIGGERED_ON]->(v:Vulnerability) RETURN inc, v",
            {"id": incident_id}, read_only=True, trace=trace,
        )
        if not rows:
            raise ToolError(f"unknown incident '{incident_id}'")
        incident, vuln = rows[0]
        audit_rows = g.run_query(
            graph,
            "MATCH (inc:Incident {id: $id})-[res:RESOLVED_BY]->(a:ActionAudit) "
            "OPTIONAL MATCH (a)-[m:MODIFIED_ENTITY]->(e) "
            "RETURN a, res, collect({edge: m, entity: e}) ORDER BY a.timestamp DESC",
            {"id": incident_id}, read_only=True, trace=trace,
        )
    audits = []
    proof_nodes: dict[Any, dict[str, Any]] = {incident["id"]: incident}
    proof_edges: list[dict[str, Any]] = []
    if vuln:
        proof_nodes[vuln["id"]] = vuln
    for audit, res_edge, modified in audit_rows:
        props = dict(audit["properties"])
        for key in ("cypher_proof", "proof_paths", "mutations"):
            try:
                props[key] = json.loads(props.get(key) or "[]")
            except (json.JSONDecodeError, TypeError):
                props[key] = []
        props["modified_entities"] = [
            {"entity": m["entity"], "previous_state": (m["edge"] or {}).get("properties", {}).get("previous_state"),
             "new_state": (m["edge"] or {}).get("properties", {}).get("new_state")}
            for m in modified if m.get("entity")
        ]
        audits.append(props)
        proof_nodes[audit["id"]] = audit
        proof_edges.append(res_edge)
        for m in modified:
            if m.get("entity"):
                proof_nodes[m["entity"]["id"]] = m["entity"]
                proof_edges.append(m["edge"])
        for p in props["proof_paths"]:
            path = p.get("path") or {}
            for n in path.get("nodes", []):
                proof_nodes[n["id"]] = n
            proof_edges.extend(path.get("edges", []))
    seen_edges: set[Any] = set()
    unique_edges = []
    for e in proof_edges:
        if e and e.get("id") not in seen_edges:
            seen_edges.add(e.get("id"))
            unique_edges.append(e)
    return _finish({
        "incident": incident["properties"] if incident else None,
        "vulnerability": vuln["properties"] if vuln else None,
        "audits": audits,
        "proof_subgraph": {"nodes": list(proof_nodes.values()), "edges": unique_edges},
    }, trace, timer)


# ======================================================================================
# 7. Ad-hoc read-only exploration
# ======================================================================================

_LIMIT_RE = re.compile(r"\bLIMIT\s+\d+", re.IGNORECASE)
READ_GRAPH_TIMEOUT_MS = 5000


def read_graph(cypher: str, limit: int = 50) -> dict[str, Any]:
    """Run an ad-hoc READ-ONLY OpenCypher query against the production graph when no other tool answers your
    question (e.g. "which services assume role X?" or "list developers on call"). Executed with GRAPH.RO_QUERY,
    so FalkorDB itself rejects any write; at most `limit` rows (max 500) are returned and the query is cancelled
    after 5 s. Labels: Vulnerability, Package,
    Function, Service, IAMRole, Database, Developer, Incident, ActionAudit. Relationships: AFFECTS, IMPORTS,
    CALLS, MAINTAINED, DEPLOYS_CODE, ROUTES_TO, ASSUMES_ROLE, CAN_ACCESS, TRIGGERED_ON, RESOLVED_BY, MODIFIED_ENTITY.
    """
    if not cypher or not cypher.strip():
        raise ToolError("cypher must not be empty")
    limit = max(1, min(int(limit), 500))
    query = cypher.strip().rstrip(";")
    if not _LIMIT_RE.search(query):
        query = f"{query} LIMIT {limit}"
    graph = g.prod_graph()
    trace: list[g.CypherTrace] = []
    with _Timer() as timer:
        try:
            result = graph.ro_query(query, timeout=READ_GRAPH_TIMEOUT_MS)
        except ResponseError as exc:
            raise ToolError(f"query rejected by FalkorDB: {exc}") from exc
        all_rows = result.result_set or []
        # the cap holds even when the query carries its own (larger) LIMIT
        rows = [[g.serialize(v) for v in row] for row in all_rows[:limit]]
        trace.append(g.CypherTrace(cypher=query, run_time_ms=float(result.run_time_ms or 0.0), row_count=len(all_rows), graph=graph.name))
    columns = [h[1] if isinstance(h, (list, tuple)) and len(h) > 1 else str(h) for h in (result.header or [])]
    return _finish({"columns": columns, "rows": rows, "row_count": len(rows), "truncated": len(all_rows) > limit}, trace, timer)


# ======================================================================================
# Non-tool helpers used by the API
# ======================================================================================


def graph_overview() -> dict[str, Any]:
    prefix = settings.graph_prefix
    graphs = []
    for name in sorted(g.list_graphs()):
        if not name.startswith(prefix):
            continue
        graph = g.get_db().select_graph(name)
        nodes = g.run_query(graph, "MATCH (n) RETURN count(n)", read_only=True)[0][0]
        edges = g.run_query(graph, "MATCH ()-[r]->() RETURN count(r)", read_only=True)[0][0]
        kind = "prod" if name == settings.prod_graph_name else "memory" if name == settings.memory_graph_name else "sandbox"
        graphs.append({"name": name, "kind": kind, "nodes": int(nodes), "edges": int(edges)})
    label_counts = g.label_counts(g.prod_graph()) if g.graph_exists(settings.prod_graph_name) else {}
    return {"graphs": graphs, "prod_graph": settings.prod_graph_name, "label_counts": label_counts}


def list_incidents() -> list[dict[str, Any]]:
    rows = g.run_query(
        g.prod_graph(),
        "MATCH (i:Incident) OPTIONAL MATCH (i)-[:TRIGGERED_ON]->(v:Vulnerability) "
        "OPTIONAL MATCH (i)-[:RESOLVED_BY]->(a:ActionAudit) "
        "RETURN i, v.id, v.severity, v.cvss, count(a) ORDER BY i.timestamp DESC",
        read_only=True,
    )
    return [{**r[0]["properties"], "cve_id": r[1], "severity": r[2], "cvss": r[3], "audit_count": int(r[4])} for r in rows]


TOOL_REGISTRY: dict[str, Callable[..., dict[str, Any]]] = {
    "find_entry_points": find_entry_points,
    "trace_blast_radius": trace_blast_radius,
    "rank_service_criticality": rank_service_criticality,
    "shortest_attack_path": shortest_attack_path,
    "expand_neighborhood": expand_neighborhood,
    "detect_service_communities": detect_service_communities,
    "find_code_owner": find_code_owner,
    "recall_similar_incidents": recall_similar_incidents,
    "simulate_remediation": simulate_remediation,
    "execute_remediation": execute_remediation,
    "rollback_remediation": rollback_remediation,
    "get_decision_proof": get_decision_proof,
    "read_graph": read_graph,
}
