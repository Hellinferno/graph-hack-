"""Regression tests for the second (fix-verification) review round."""
from __future__ import annotations

import dataclasses

import httpx
import pytest
from fastapi.testclient import TestClient

from aegis import graph as g
from aegis import tools
from aegis.agent import AgentRunner
from aegis.api import app, state
from aegis.seed import DEMO_CVE_ID, DEMO_INCIDENT_ID, HISTORICAL_INCIDENT_ID

from .openrouter_fake import turn

BRIDGE, ROLE = "legacy-billing-bridge", "LegacyBillingBridgeAdmin"
WHY = "all six exposure paths pass through the legacy bridge; sandbox proved 6 -> 0"


def _status(cypher: str, **params):
    return g.run_query(g.prod_graph(), cypher, params, read_only=True)


def _two_overlapping_actions():
    """A1 isolates legacy-billing-bridge; A2 then isolates reporting-adapter, sharing the legacy -> reporting route."""
    tools.simulate_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, BRIDGE, ROLE)
    a1 = tools.execute_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, BRIDGE, ROLE, WHY)
    sim = tools.simulate_remediation(HISTORICAL_INCIDENT_ID, "CVE-2026-4102", "reporting-adapter", "ReportingReadOnly")
    assert sim["safe_to_execute"], sim["unsafe_reasons"]
    a2 = tools.execute_remediation(HISTORICAL_INCIDENT_ID, "CVE-2026-4102", "reporting-adapter", "ReportingReadOnly",
                                   "the two remaining SQLi paths start at reporting-adapter; sandbox proved 2 -> 0")
    assert a1["status"] == a2["status"] == "ACTION_EXECUTED"
    return a1, a2


def test_seeded_history_does_not_lock_entities_and_shared_edges_are_refcounted(fresh_graphs):
    a1, a2 = _two_overlapping_actions()
    shared = "MATCH (:Service {name: 'legacy-billing-bridge'})-[r:ROUTES_TO]->(:Service {name: 'reporting-adapter'}) RETURN r.status, r.held_by"
    assert _status(shared)[0] == ["ISOLATED_BY_AEGIS", [a1["audit_id"], a2["audit_id"]]]

    # rolling back A1 must not reopen the route into reporting-adapter, which A2 still isolates
    rb1 = tools.rollback_remediation(a1["audit_id"])
    assert any(m["why"] == "still held by another active action" for m in rb1["skipped"])
    assert _status(shared)[0] == ["ISOLATED_BY_AEGIS", [a2["audit_id"]]]

    # the seeded historical audit (AUDIT-SEED-077) must not keep reporting-adapter / ReportingReadOnly locked
    rb2 = tools.rollback_remediation(a2["audit_id"])
    assert rb2["skipped"] == []
    assert _status("MATCH (s:Service {name: 'reporting-adapter'}), (r:IAMRole {name: 'ReportingReadOnly'}) RETURN s.status, r.status")[0] == ["HEALTHY", "ACTIVE"]
    assert _status(shared)[0] == ["ACTIVE", None]
    leftovers = _status("MATCH ()-[r]->() WHERE r.held_by IS NOT NULL OR r.status ENDS WITH '_BY_AEGIS' RETURN count(r)")[0][0]
    assert leftovers == 0
    assert tools.trace_blast_radius(DEMO_CVE_ID)["total_paths"] == 6


def test_sandboxes_are_pruned_and_never_leaked(fresh_graphs, monkeypatch):
    monkeypatch.setattr(tools, "settings", dataclasses.replace(tools.settings, keep_sandbox=True))
    for _ in range(5):
        tools.simulate_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, BRIDGE, ROLE)
    prefix = g.sim_graph_name(DEMO_INCIDENT_ID) + "_"
    assert len([n for n in g.list_graphs() if n.startswith(prefix)]) == tools.KEEP_SANDBOXES_PER_INCIDENT

    monkeypatch.setattr(tools, "settings", dataclasses.replace(tools.settings, keep_sandbox=False))
    before = set(g.list_graphs())

    def boom(*_a, **_k):
        raise RuntimeError("simulated failure inside the sandbox")

    monkeypatch.setattr(tools, "_exposure_count", boom)
    with pytest.raises(RuntimeError):
        tools.simulate_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, BRIDGE, ROLE)
    assert set(g.list_graphs()) == before  # the failed simulation's sandbox was deleted


async def test_openrouter_failure_mid_run_is_an_error_not_an_all_clear(openrouter, fresh_graphs):
    openrouter([
        turn("", [("c1", "trace_blast_radius", {"cve_id": DEMO_CVE_ID})]),
        httpx.Response(429, json={"error": {"code": 429, "message": "Rate limit exceeded: free-models-per-day"}}, headers={"retry-after": "7200"}),
    ])
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    err = next(e for e in events if e["type"] == "error")
    assert "resets in about 120 min" in err["message"] and "rate limit" in err["message"]
    assert events[-1]["outcome"] == "ERROR"
    stages = {e["name"]: e["status"] for e in events if e["type"] == "stage"}
    assert "started" not in stages.values()  # every stage was closed


async def test_openrouter_refused_turn_text_is_never_the_verdict(openrouter, fresh_graphs):
    openrouter([turn("I can't help with this.", finish="content_filter")])
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    done = events[-1]
    assert done["outcome"] == "ERROR" and "I can't help" not in done["summary"]


async def test_openrouter_echoes_only_valid_json_arguments(openrouter, fresh_graphs):
    fake = openrouter([
        turn("", [("bad1", "execute_remediation", '{"incident_id": "INC-2026-091", ')]),
        turn("", [("t1", "simulate_remediation", '{"incident_id": "INC-2026-091"')], finish="length"),
        turn("Stopping."),
    ])
    [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    echoed = [m for m in fake.chat_requests[2]["messages"] if m["role"] == "assistant" and m.get("tool_calls")]
    assert [tc["function"]["arguments"] for m in echoed for tc in m["tool_calls"]] == ["{}", "{}"]


async def test_openrouter_moderation_and_unreadable_bodies(openrouter, fresh_graphs):
    fake = openrouter([httpx.Response(200, text="<html>gateway hiccup</html>"), turn("Nothing to do.")])
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    assert len(fake.chat_requests) == 2 and "error" not in [e["type"] for e in events]

    openrouter([httpx.Response(403, json={"error": {"code": 403, "message": "Input was flagged"}})])
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    err = next(e for e in events if e["type"] == "error")
    assert "moderation" in err["message"] and "OPENROUTER_API_KEY" not in err["message"]


def test_runs_are_refused_while_reseeding_and_preview_origin_is_allowed():
    with TestClient(app) as client:
        state.reseeding = True
        try:
            assert client.post("/api/runs", json={"incident_id": DEMO_INCIDENT_ID, "mode": "deterministic"}).status_code == 409
        finally:
            state.reseeding = False
        assert client.post("/api/seed", json={}, headers={"Origin": "http://localhost:4173"}).status_code == 200
