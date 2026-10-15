from __future__ import annotations

from aegis import tools
from aegis.agent import AgentRunner
from aegis.memory import memory_overview
from aegis.seed import DEMO_CVE_ID, DEMO_INCIDENT_ID


async def test_deterministic_run_mitigates_incident_through_mcp(fresh_graphs):
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "deterministic")]
    types = [e["type"] for e in events]
    assert types[0] == "run_started" and types[-1] == "run_completed"
    assert "error" not in types

    calls = [e["name"] for e in events if e["type"] == "tool_call"]
    assert calls == [
        "find_entry_points", "recall_similar_incidents", "trace_blast_radius", "rank_service_criticality", "find_code_owner",
        "shortest_attack_path", "simulate_remediation", "execute_remediation", "trace_blast_radius",
    ]
    results = {e["name"]: e for e in events if e["type"] == "tool_result"}
    assert all(not e["is_error"] for e in results.values())

    stages = [(e["stage"], e["status"]) for e in events if e["type"] == "stage"]
    assert [s for s in stages if s[1] == "started"] == [(1, "started"), (2, "started"), (3, "started"), (4, "started"), (5, "started")]
    assert all(status == "completed" for _, status in [s for s in stages if s[1] != "started"])

    decision = next(e for e in events if e["type"] == "decision")
    assert decision["bridge_service"] == "legacy-billing-bridge" and decision["iam_role"] == "LegacyBillingBridgeAdmin"
    assert decision["sim_passed"] is True and decision["code_owner"]["handle"] == "@aarav-sec"
    assert decision["scores"]["betweenness"] > 0

    styles = [e["style"] for e in events if e["type"] == "graph_highlight"]
    assert styles[:1] == ["attack"] and "quarantined" in styles and "safe" in styles and "chokepoint" in styles

    done = events[-1]
    assert done["outcome"] == "MITIGATED" and done["audit_id"] and done["tool_call_count"] == 9
    assert tools.trace_blast_radius(DEMO_CVE_ID)["total_paths"] == 0

    mem = memory_overview()
    episode = next(e for e in mem["episodes"] if e["id"] == done["episode_id"])
    assert episode["outcome"] == "MITIGATED" and episode["tool_call_count"] == 9
    assert [c["name"] for c in sorted(episode["tool_calls"], key=lambda c: c["seq"])] == calls
    assert any(p["signature"] == "package:jwt-crypto-core" for p in mem["playbooks"])

    rb = tools.rollback_remediation(done["audit_id"])
    assert rb["status"] == "ROLLED_BACK"
    assert tools.trace_blast_radius(DEMO_CVE_ID)["total_paths"] == 6


async def test_run_unknown_incident_reports_error():
    events = [ev async for ev in AgentRunner().run("INC-0000-000", None, "deterministic")]
    assert events[0]["type"] == "error" and "unknown incident" in events[0]["message"]


async def test_llm_mode_without_key_is_refused():
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    assert events[0]["type"] == "error" and "ANTHROPIC_API_KEY" in events[0]["message"]
