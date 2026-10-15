"""Regression tests for the issues confirmed by the multi-agent code review (one test per defect)."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from aegis import graph as g
from aegis import memory, tools
from aegis.agent import AgentRunner
from aegis.api import AppState, RunRecord, app, state, stream_events
from aegis.config import settings
from aegis.embeddings import cosine_distance, embed
from aegis.mcp_client import MCPToolbox, ToolCallResult
from aegis.seed import DEMO_CVE_ID, DEMO_INCIDENT_ID

BRIDGE, ROLE = "legacy-billing-bridge", "LegacyBillingBridgeAdmin"
WHY = "all six exposure paths pass through the legacy bridge; sandbox proved 6 -> 0"


# ----------------------------------------------------------------------------- graph tools


def test_vacuous_simulation_is_not_safe_and_gate_is_bound_to_the_cve(fresh_graphs):
    # CVE-2026-0193 has no exposure at all: a simulation of it proves nothing and must not pass
    sim = tools.simulate_remediation(DEMO_INCIDENT_ID, "CVE-2026-0193", "reporting-adapter", "ReportingReadOnly")
    assert sim["exposure_before"] == 0 and sim["safe_to_execute"] is False
    assert any("no active exposure" in r for r in sim["unsafe_reasons"])
    # ...and cannot authorise acting on a different CVE
    res = tools.execute_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, "reporting-adapter", "ReportingReadOnly", WHY)
    assert res["status"] == "REFUSED" and DEMO_CVE_ID in res["reason"]
    assert tools.trace_blast_radius(DEMO_CVE_ID)["total_paths"] == 6


def test_role_must_be_assumed_by_the_bridge(fresh_graphs):
    with pytest.raises(tools.ToolError, match="does not assume"):
        tools.simulate_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, BRIDGE, "PaymentReadWriteRole")


def test_role_shared_with_a_critical_service_is_never_quarantined(fresh_graphs):
    # telemetry-audit-sync (standard) shares PaymentReadWriteRole with payment-orchestrator (critical)
    sim = tools.simulate_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, "telemetry-audit-sync", "PaymentReadWriteRole")
    assert sim["safe_to_execute"] is False and sim["role_shared_with_critical"] == ["payment-orchestrator"]
    res = tools.execute_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, "telemetry-audit-sync", "PaymentReadWriteRole", WHY)
    assert res["status"] == "REFUSED" and "critical-tier" in res["reason"]


def test_second_action_on_isolated_entities_is_refused_and_rollback_restores_everything(fresh_graphs):
    tools.simulate_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, BRIDGE, ROLE)
    first = tools.execute_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, BRIDGE, ROLE, WHY)
    assert first["status"] == "ACTION_EXECUTED" and first["playbook"] == "package:jwt-crypto-core"
    again = tools.execute_remediation(DEMO_INCIDENT_ID, "CVE-2026-4102", BRIDGE, ROLE, WHY)
    assert again["status"] == "REFUSED" and "already isolated" in again["reason"]
    rb = tools.rollback_remediation(first["audit_id"])
    assert len(rb["restored"]) == 7 and rb["skipped"] == [] and rb["incident_status"] == "OPEN"
    rows = g.run_query(g.prod_graph(), "MATCH (s:Service {name: $b}), (r:IAMRole {name: $r}) RETURN s.status, r.status",
                       {"b": BRIDGE, "r": ROLE}, read_only=True)
    assert rows[0] == ["HEALTHY", "ACTIVE"]


def test_unverified_action_is_partial_and_does_not_mitigate(fresh_graphs):
    sim = tools.simulate_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, BRIDGE, ROLE)
    assert sim["safe_to_execute"]
    # production drifts after the simulation: a new route bypasses the bridge
    g.run_query(g.prod_graph(), "MATCH (a:Service {name: 'auth-token-service'}), (r:Service {name: 'reporting-adapter'}) "
                                "CREATE (a)-[:ROUTES_TO {status: 'ACTIVE', is_critical_path: false, protocol: 'http'}]->(r)")
    res = tools.execute_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, BRIDGE, ROLE, WHY)
    assert res["status"] == "PARTIAL" and res["verification"]["exposed_paths_after"] > 0
    assert res["incident_status"] == "OPEN" and res["playbook"] is None and "remain" in res["reason"]
    assert memory.recall(package_name="jwt-crypto-core")["playbooks"] == []
    assert tools.rollback_remediation(res["audit_id"])["status"] == "ROLLED_BACK"


def test_read_graph_caps_rows_even_with_its_own_limit():
    res = tools.read_graph("MATCH (n) RETURN n.name LIMIT 1000", limit=5)
    assert res["row_count"] == 5 and res["truncated"] is True


def test_embeddings_keep_morphological_variants_close():
    assert cosine_distance(embed("serialization"), embed("deserialization deserialization")) < 0.6
    assert cosine_distance(embed("token forgery"), embed("forged tokens")) < 0.8


def test_concurrent_simulations_get_their_own_sandboxes(fresh_graphs):
    a = tools.simulate_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, BRIDGE, ROLE)
    b = tools.simulate_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, BRIDGE, ROLE)
    assert a["sandbox_graph"] != b["sandbox_graph"] and a["sandbox_graph"].startswith(f"{settings.graph_prefix}sim_{DEMO_INCIDENT_ID}_")


# ----------------------------------------------------------------------------- agent


async def test_weak_alert_falls_back_to_the_incident_cve(fresh_graphs):
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, "Disk usage at 97 percent on node-7, pod evicted", "deterministic")]
    traced = [e["args"]["cve_id"] for e in events if e["type"] == "tool_call" and e["name"] == "trace_blast_radius"]
    assert traced and set(traced) == {DEMO_CVE_ID}
    done = events[-1]
    assert done["outcome"] == "MITIGATED" and "did not anchor strongly" in done["summary"]


class _FailingToolbox:
    """MCP toolbox stand-in whose trace_blast_radius call fails (e.g. the MCP subprocess died)."""

    started = True
    dead = False
    servers = ["aegisgraph"]

    def __init__(self) -> None:
        self.real = MCPToolbox(include_falkordb_server=False)

    def list_tools(self):
        return self.real.list_tools()

    async def call_tool(self, name, args=None):
        if name == "trace_blast_radius":
            return ToolCallResult(name=name, args=args or {}, result={"error": "MCPError: Connection closed"}, is_error=True, duration_ms=1.0, server="aegisgraph")
        return await self.real.call_tool(name, args)


async def test_failed_required_tool_is_an_error_not_an_all_clear(fresh_graphs):
    box = _FailingToolbox()
    await box.real.start()
    try:
        events = [ev async for ev in AgentRunner(toolbox=box).run(DEMO_INCIDENT_ID, None, "deterministic")]
    finally:
        await box.real.stop()
    assert any(e["type"] == "error" and "trace_blast_radius failed" in e["message"] for e in events)
    done = events[-1]
    assert done["type"] == "run_completed" and done["outcome"] == "ERROR"
    ep = next(e for e in memory.memory_overview()["episodes"] if e["id"] == done["episode_id"])
    assert ep["outcome"] == "ERROR"  # the stored episode matches run_completed


async def test_episodes_link_simulations_and_playbooks(fresh_graphs):
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "deterministic", run_id="run-fixed-id")]
    assert {e["run_id"] for e in events} == {"run-fixed-id"}
    episode_id = events[-1]["episode_id"]
    rows = g.run_query(g.memory_graph(),
                       "MATCH (e:Episode {id: $id}) OPTIONAL MATCH (e)-[:RAN_SIMULATION]->(s) OPTIONAL MATCH (e)-[:APPLIED_PLAYBOOK]->(p) "
                       "RETURN e.cve_id, count(DISTINCT s), collect(DISTINCT p.signature)", {"id": episode_id}, read_only=True)
    assert rows[0] == [DEMO_CVE_ID, 1, ["package:jwt-crypto-core"]]


# ----------------------------------------------------------------------------- MCP client


async def test_dead_mcp_server_is_detected_and_respawned():
    st = AppState()
    box = await st.get_toolbox()
    handle = next(iter(box._tool_index.values()))[0]

    async def boom(*_a, **_k):
        raise ConnectionError("Connection closed")

    handle.session.call_tool = boom
    res = await box.call_tool("rank_service_criticality", {})
    assert res.is_error and box.dead
    fresh = await st.get_toolbox()
    try:
        assert fresh is not box and not fresh.dead
        assert not (await fresh.call_tool("rank_service_criticality", {})).is_error
    finally:
        await st.shutdown()


def test_official_falkordb_server_is_read_only():
    params = MCPToolbox.falkordb_server_params()
    if params is None:
        pytest.skip("official FalkorDB MCP server not installed")
    assert params.env["FALKORDB_STRICT_READONLY"] == "true" and params.env["FALKORDB_DEFAULT_READONLY"] == "true"


# ----------------------------------------------------------------------------- API


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_cross_site_writes_are_rejected(client):
    assert client.post("/api/seed", headers={"Origin": "http://evil.example"}).status_code == 403
    assert client.post("/api/seed", json={}, headers={"Origin": "http://localhost:5173"}).status_code == 200
    assert client.post("/api/seed", json={}, headers={"Origin": "http://127.0.0.1:5173"}).status_code == 200
    assert client.get("/api/health", headers={"Origin": "http://evil.example"}).status_code == 200


def test_reseed_refused_while_a_run_is_in_progress(client):
    state.runs["run-busy"] = RunRecord(run_id="run-busy", incident_id=DEMO_INCIDENT_ID, mode="deterministic", status="running")
    try:
        assert client.post("/api/seed", json={}).status_code == 409
    finally:
        del state.runs["run-busy"]


def test_api_run_id_matches_event_run_id(client, fresh_graphs):
    run_id = client.post("/api/runs", json={"incident_id": DEMO_INCIDENT_ID, "mode": "deterministic"}).json()["run_id"]
    deadline = time.time() + 120
    while client.get(f"/api/runs/{run_id}").json()["status"] == "running" and time.time() < deadline:
        time.sleep(0.3)
    events = client.get(f"/api/runs/{run_id}").json()["events"]
    assert events and {e["run_id"] for e in events} == {run_id}


async def test_sse_delivers_events_queued_during_replay():
    record = RunRecord(run_id="run-sse", incident_id=DEMO_INCIDENT_ID, mode="deterministic")
    record.events.append({"type": "run_started", "run_id": "run-sse"})
    state.runs[record.run_id] = record
    try:
        response = await stream_events(record.run_id)
        it = response.body_iterator
        first = await it.__anext__()
        assert "run_started" in first
        # while the client is still reading the replay, the run emits its tail and finishes
        tail = {"type": "run_completed", "run_id": "run-sse", "outcome": "MITIGATED"}
        record.events.append(tail)
        for q in list(record.subscribers):
            q.put_nowait(tail)
        record.status = "completed"
        for q in list(record.subscribers):
            q.put_nowait(None)
        rest = [chunk async for chunk in it]
        assert any("run_completed" in c for c in rest) and rest[-1].startswith("event: done")
    finally:
        del state.runs[record.run_id]


# ----------------------------------------------------------------------------- CLI


def test_cli_seed_keeps_memory_unless_asked(capsys):
    from aegis.__main__ import main

    g.run_query(g.memory_graph(), "CREATE (:Playbook {signature: 'package:cli-keep', success_count: 1, last_used: 0})")
    assert main(["seed"]) == 0
    assert g.run_query(g.memory_graph(), "MATCH (p:Playbook {signature: 'package:cli-keep'}) RETURN count(p)", read_only=True)[0][0] == 1
    assert main(["seed", "--reset-memory"]) == 0
    assert g.run_query(g.memory_graph(), "MATCH (p:Playbook {signature: 'package:cli-keep'}) RETURN count(p)", read_only=True)[0][0] == 0
    out = capsys.readouterr().out
    assert out.count('"prod"') == 2 and '"Service": 10' in out
