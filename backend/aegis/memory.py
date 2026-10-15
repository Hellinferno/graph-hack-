"""Cross-session agent memory stored in FalkorDB (``<prefix>memory_graph``).

Episodic memory: every agent run is an ``Episode`` linked to the ``ToolCall`` nodes it made (what the agent
did, in order, with digests of the results). Procedural memory: ``Simulation`` outcomes and ``Playbook``
nodes (a remediation pattern that passed its counterfactual check and was executed) keyed by a signature
such as ``package:jwt-crypto-core`` so a later incident on the same package can reuse it.

The ``execute_remediation`` guardrail also lives here: an action is only allowed if a passing ``Simulation``
for the same incident/bridge/role exists within ``settings.sim_ttl_minutes``.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

from . import graph as g
from .config import settings

log = logging.getLogger("aegis.memory")

MEMORY_INDEXES: list[str] = [
    "CREATE INDEX FOR (e:Episode) ON (e.id)",
    "CREATE INDEX FOR (e:Episode) ON (e.incident_id)",
    "CREATE INDEX FOR (s:Simulation) ON (s.id)",
    "CREATE INDEX FOR (s:Simulation) ON (s.incident_id)",
    "CREATE INDEX FOR (p:Playbook) ON (p.signature)",
    "CREATE INDEX FOR (t:ToolCall) ON (t.id)",
]

def _graph():
    """The memory graph. Creates it (with its indexes) when missing: FalkorDB rejects read-only queries on a
    graph key that does not exist, and the memory graph may be dropped by a reseed at any time."""
    graph = g.memory_graph()
    if not g.graph_exists(settings.memory_graph_name):
        from .seed import create_indexes  # local import: seed imports graph/embeddings only, no cycle

        create_indexes(graph, MEMORY_INDEXES)
    return graph


def new_id(prefix: str) -> str:
    return f"{prefix}-{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}"


def _digest(value: Any, limit: int = 300) -> str:
    try:
        text = json.dumps(value, default=str, sort_keys=True)
    except TypeError:
        text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


# --------------------------------------------------------------------------------------
# Episodes + tool calls
# --------------------------------------------------------------------------------------


def start_episode(incident_id: str, cve_id: str | None, mode: str) -> str:
    episode_id = new_id("EP")
    g.run_query(
        _graph(),
        "CREATE (:Episode {id: $id, incident_id: $incident_id, cve_id: $cve_id, started_at: $ts, finished_at: 0, "
        "mode: $mode, outcome: 'RUNNING', summary: '', tool_call_count: 0})",
        {"id": episode_id, "incident_id": incident_id, "cve_id": cve_id or "", "ts": int(time.time()), "mode": mode},
    )
    return episode_id


def record_tool_call(
    episode_id: str | None,
    seq: int,
    name: str,
    args: dict[str, Any],
    result: Any,
    duration_ms: float,
    is_error: bool = False,
) -> str | None:
    if not episode_id:
        return None
    call_id = new_id("TC")
    g.run_query(
        _graph(),
        "MATCH (e:Episode {id: $episode_id}) "
        "CREATE (t:ToolCall {id: $id, seq: $seq, name: $name, args_json: $args, result_digest: $digest, "
        "duration_ms: $ms, is_error: $is_error, ts: $ts}) "
        "CREATE (e)-[:USED_TOOL {seq: $seq}]->(t) "
        "SET e.tool_call_count = e.tool_call_count + 1",
        {
            "episode_id": episode_id, "id": call_id, "seq": seq, "name": name, "args": _digest(args, 1000),
            "digest": _digest(result), "ms": round(float(duration_ms), 2), "is_error": bool(is_error),
            "ts": int(time.time()),
        },
    )
    return call_id


def finish_episode(episode_id: str | None, outcome: str, summary: str, cve_id: str | None = None) -> None:
    """Close an episode. ``cve_id`` records the CVE actually investigated (it can differ from the incident's)."""
    if not episode_id:
        return
    g.run_query(
        _graph(),
        "MATCH (e:Episode {id: $id}) SET e.finished_at = $ts, e.outcome = $outcome, e.summary = $summary, "
        "e.cve_id = CASE WHEN $cve_id IS NULL OR $cve_id = '' THEN e.cve_id ELSE $cve_id END",
        {"id": episode_id, "ts": int(time.time()), "outcome": outcome, "summary": summary[:2000], "cve_id": cve_id},
    )


def link_simulation(episode_id: str | None, simulation_id: str | None) -> None:
    """(Episode)-[:RAN_SIMULATION]->(Simulation): which run produced which sandbox proof."""
    if not episode_id or not simulation_id:
        return
    g.run_query(
        _graph(),
        "MATCH (e:Episode {id: $episode_id}), (s:Simulation {id: $sim_id}) MERGE (e)-[:RAN_SIMULATION]->(s)",
        {"episode_id": episode_id, "sim_id": simulation_id},
    )


def link_playbook(episode_id: str | None, signature: str | None) -> None:
    """(Episode)-[:APPLIED_PLAYBOOK]->(Playbook): which run produced or reinforced which playbook."""
    if not episode_id or not signature:
        return
    g.run_query(
        _graph(),
        "MATCH (e:Episode {id: $episode_id}), (p:Playbook {signature: $signature}) MERGE (e)-[:APPLIED_PLAYBOOK]->(p)",
        {"episode_id": episode_id, "signature": signature},
    )


# --------------------------------------------------------------------------------------
# Simulations (procedural memory + execute guardrail)
# --------------------------------------------------------------------------------------


def record_simulation(sim: dict[str, Any], episode_id: str | None = None, trace: list[g.CypherTrace] | None = None) -> None:
    g.run_query(
        _graph(),
        "CREATE (s:Simulation {id: $id, incident_id: $incident_id, cve_id: $cve_id, timestamp: $ts, "
        "bridge_service: $bridge, iam_role: $role, safe: $safe, exposure_closed: $closed, "
        "critical_flows_intact: $flows, critical_services_connected: $connected, sandbox_graph: $sandbox, "
        "exposure_before: $before, exposure_after: $after})",
        {
            "id": sim["simulation_id"], "incident_id": sim["incident_id"], "cve_id": sim.get("cve_id", ""),
            "ts": int(time.time()), "bridge": sim["bridge_service"], "role": sim["iam_role"],
            "safe": bool(sim["safe_to_execute"]), "closed": bool(sim["exposure_closed"]),
            "flows": bool(sim["critical_flows_intact"]), "connected": bool(sim["critical_services_connected"]),
            "sandbox": sim.get("sandbox_graph", ""), "before": int(sim["exposure_before"]), "after": int(sim["exposure_after"]),
        },
        trace=trace,
    )
    link_simulation(episode_id, sim["simulation_id"])


def latest_passing_simulation(
    incident_id: str,
    cve_id: str,
    bridge_service: str,
    iam_role: str,
    ttl_minutes: int | None = None,
    trace: list[g.CypherTrace] | None = None,
) -> dict[str, Any] | None:
    """The simulate-before-act gate: a passing simulation of exactly this incident, CVE, bridge and role, recent enough."""
    ttl = settings.sim_ttl_minutes if ttl_minutes is None else ttl_minutes
    cutoff = int(time.time()) - ttl * 60
    rows = g.run_query(
        _graph(),
        "MATCH (s:Simulation {incident_id: $incident_id, cve_id: $cve_id, bridge_service: $bridge, iam_role: $role}) "
        "WHERE s.safe = true AND s.timestamp >= $cutoff "
        "RETURN s ORDER BY s.timestamp DESC LIMIT 1",
        {"incident_id": incident_id, "cve_id": cve_id, "bridge": bridge_service, "role": iam_role, "cutoff": cutoff},
        read_only=True, trace=trace,
    )
    return rows[0][0]["properties"] if rows else None


def sandboxes_for_incident(incident_id: str, prefix: str) -> list[str]:
    """Sandbox graph names recorded by this incident's simulations, newest first."""
    rows = g.run_query(
        _graph(),
        "MATCH (s:Simulation {incident_id: $id}) WHERE s.sandbox_graph STARTS WITH $prefix "
        "RETURN s.sandbox_graph ORDER BY s.timestamp DESC, s.id DESC",
        {"id": incident_id, "prefix": prefix}, read_only=True,
    )
    return list(dict.fromkeys(r[0] for r in rows))


# --------------------------------------------------------------------------------------
# Playbooks
# --------------------------------------------------------------------------------------


def upsert_playbook(
    signature: str,
    action_type: str,
    bridge_service: str,
    iam_role: str,
    incident_id: str,
    simulation_id: str | None = None,
    episode_id: str | None = None,
    trace: list[g.CypherTrace] | None = None,
) -> dict[str, Any]:
    rows = g.run_query(
        _graph(),
        "MERGE (p:Playbook {signature: $signature}) "
        "ON CREATE SET p.success_count = 0 "
        "SET p.action_type = $action_type, p.bridge_service = $bridge, p.iam_role = $role, "
        "    p.success_count = coalesce(p.success_count, 0) + 1, p.last_used = $ts, p.last_incident_id = $incident_id "
        "RETURN p",
        {
            "signature": signature, "action_type": action_type, "bridge": bridge_service, "role": iam_role,
            "ts": int(time.time()), "incident_id": incident_id,
        },
        trace=trace,
    )
    if simulation_id:
        g.run_query(
            _graph(),
            "MATCH (p:Playbook {signature: $signature}), (s:Simulation {id: $sim_id}) MERGE (p)-[:DERIVED_FROM]->(s)",
            {"signature": signature, "sim_id": simulation_id},
            trace=trace,
        )
    link_playbook(episode_id, signature)
    return rows[0][0]["properties"] if rows else {}


def recall(cve_id: str | None = None, package_name: str | None = None, limit: int = 5,
           trace: list[g.CypherTrace] | None = None) -> dict[str, Any]:
    """Procedural + episodic recall for a new incident."""
    graph = _graph()
    if package_name:
        playbooks = g.run_query(
            graph,
            "MATCH (p:Playbook) WHERE p.signature = $sig RETURN p ORDER BY p.last_used DESC LIMIT $limit",
            {"sig": f"package:{package_name}", "limit": limit}, read_only=True, trace=trace,
        )
    else:
        playbooks = g.run_query(graph, "MATCH (p:Playbook) RETURN p ORDER BY p.last_used DESC LIMIT $limit", {"limit": limit}, read_only=True, trace=trace)
    if cve_id:
        episodes = g.run_query(
            graph,
            "MATCH (e:Episode) WHERE e.cve_id = $cve AND e.outcome <> 'RUNNING' "
            "OPTIONAL MATCH (e)-[:USED_TOOL]->(t:ToolCall) "
            "WITH e, t ORDER BY t.seq "
            "RETURN e, collect(t.name) ORDER BY e.started_at DESC LIMIT $limit",
            {"cve": cve_id, "limit": limit}, read_only=True, trace=trace,
        )
    else:
        episodes = g.run_query(
            graph,
            "MATCH (e:Episode) WHERE e.outcome <> 'RUNNING' OPTIONAL MATCH (e)-[:USED_TOOL]->(t:ToolCall) "
            "WITH e, t ORDER BY t.seq RETURN e, collect(t.name) ORDER BY e.started_at DESC LIMIT $limit",
            {"limit": limit}, read_only=True, trace=trace,
        )
    return {
        "playbooks": [row[0]["properties"] for row in playbooks],
        "episodes": [{**row[0]["properties"], "tools_used": row[1]} for row in episodes],
    }


def memory_overview(limit: int = 25) -> dict[str, Any]:
    graph = _graph()
    episodes = g.run_query(
        graph,
        "MATCH (e:Episode) OPTIONAL MATCH (e)-[:USED_TOOL]->(t:ToolCall) WITH e, t ORDER BY t.seq "
        "RETURN e, collect({seq: t.seq, name: t.name, duration_ms: t.duration_ms, is_error: t.is_error, args: t.args_json, digest: t.result_digest}) "
        "ORDER BY e.started_at DESC LIMIT $limit",
        {"limit": limit}, read_only=True,
    )
    playbooks = g.run_query(graph, "MATCH (p:Playbook) RETURN p ORDER BY p.last_used DESC", read_only=True)
    simulations = g.run_query(graph, "MATCH (s:Simulation) RETURN s ORDER BY s.timestamp DESC LIMIT $limit", {"limit": limit}, read_only=True)
    return {
        "graph": graph.name,
        "counts": g.label_counts(graph),
        "episodes": [
            {**row[0]["properties"], "tool_calls": [c for c in row[1] if c.get("name") is not None]} for row in episodes
        ],
        "playbooks": [row[0]["properties"] for row in playbooks],
        "simulations": [row[0]["properties"] for row in simulations],
    }
