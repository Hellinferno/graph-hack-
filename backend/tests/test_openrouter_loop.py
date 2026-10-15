"""OpenRouter LLM-mode tests with httpx.MockTransport standing in for https://openrouter.ai/api/v1.

The scripted model replies follow the OpenAI-compatible chat-completions shape OpenRouter returns
(choices[0].message.{content, reasoning, tool_calls}, finish_reason). Tools still run for real over MCP on live FalkorDB.
"""
from __future__ import annotations

import json

import httpx

from aegis import llm_openrouter as orc
from aegis import tools
from aegis.agent import AgentRunner
from aegis.config import _resolve_provider
from aegis.seed import DEMO_CVE_ID, DEMO_INCIDENT_ID

from .openrouter_fake import FREE_MODELS, turn

JUSTIFICATION = "All 6 exposure paths pass through legacy-billing-bridge (betweenness 6.0); payment-orchestrator is critical; sandbox 6 -> 0."
SIM_ARGS = {"incident_id": DEMO_INCIDENT_ID, "cve_id": DEMO_CVE_ID, "bridge_service": "legacy-billing-bridge", "iam_role": "LegacyBillingBridgeAdmin"}


async def test_openrouter_doctrine_closes_the_loop(openrouter, fresh_graphs):
    fake = openrouter([
        turn("Anchoring the alert.", [("c1", "find_entry_points", {"alert_text": "forged JWT bearer tokens; jwt-crypto-core bypass"})],
             reasoning="Start by anchoring the alert in the graph."),
        turn("", [("c2", "trace_blast_radius", {"cve_id": DEMO_CVE_ID})]),
        turn("", [("c3", "rank_service_criticality", {}), ("c4", "find_code_owner", {"cve_id": DEMO_CVE_ID})], model=FREE_MODELS[1]),
        turn("", [("c5", "simulate_remediation", SIM_ARGS)]),
        turn("", [("c6", "execute_remediation", {**SIM_ARGS, "justification": JUSTIFICATION})]),
        turn("", [("c7", "trace_blast_radius", {"cve_id": DEMO_CVE_ID})]),
        turn("Contained CVE-2026-8841: exposure 6 -> 0, PR routed to @aarav-sec."),
    ])
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    types = [e["type"] for e in events]
    assert events[0]["type"] == "run_started" and events[0]["model"] == FREE_MODELS[0] and events[0]["provider"] == "openrouter"
    assert "error" not in types, [e for e in events if e["type"] == "error"]
    assert [e["name"] for e in events if e["type"] == "tool_call"] == [
        "find_entry_points", "trace_blast_radius", "rank_service_criticality", "find_code_owner",
        "simulate_remediation", "execute_remediation", "trace_blast_radius"]
    assert any(e["type"] == "thinking" and "anchoring" in e["text"] for e in events)
    assert any(e["type"] == "assistant_text" and f"[model: {FREE_MODELS[1]}]" in e["text"] for e in events)
    decision = next(e for e in events if e["type"] == "decision")
    assert decision["bridge_service"] == "legacy-billing-bridge"
    done = events[-1]
    assert done["outcome"] == "MITIGATED" and done["audit_id"] and done["summary"].startswith("Contained CVE-2026-8841")
    assert tools.trace_blast_radius(DEMO_CVE_ID)["total_paths"] == 0

    assert fake.model_list_calls == 1 and len(fake.chat_requests) == 7
    first = fake.chat_requests[0]
    assert first["models"] == FREE_MODELS and "model" not in first
    assert first["tool_choice"] == "auto" and first["reasoning"] == {"effort": "medium"}
    assert first["messages"][0]["role"] == "system" and first["messages"][1]["role"] == "user"
    assert {t["function"]["name"] for t in first["tools"]} == set(tools.TOOL_REGISTRY)
    assert all(t["type"] == "function" and t["function"]["parameters"]["type"] == "object" for t in first["tools"])
    # parallel calls: the assistant turn is echoed with both tool_calls, then one tool message per call, ids matched
    fourth = fake.chat_requests[3]["messages"]
    assert [tc["id"] for tc in fourth[-3]["tool_calls"]] == ["c3", "c4"]
    assert [(m["role"], m["tool_call_id"]) for m in fourth[-2:]] == [("tool", "c3"), ("tool", "c4")]
    payload = json.loads(fourth[-2]["content"])
    assert "betweenness" in payload and "cypher" not in payload


async def test_openrouter_refuses_paid_models(openrouter, fresh_graphs):
    fake = openrouter([], openrouter_model="openai/some-paid-model", openrouter_fallbacks=())
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    assert any(e["type"] == "error" and "refusing non-free" in e["message"] for e in events)
    assert fake.chat_requests == [] and events[-1]["outcome"] == "ERROR"


async def test_openrouter_retries_rate_limit(openrouter, fresh_graphs):
    fake = openrouter([
        httpx.Response(429, json={"error": {"code": 429, "message": "Rate limit exceeded"}}, headers={"retry-after": "1"}),
        turn("Nothing to do yet."),
    ])
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    assert len(fake.chat_requests) == 2
    assert "error" not in [e["type"] for e in events]
    assert events[-1]["outcome"] == "NO_ACTION"


async def test_openrouter_invalid_arguments_are_not_executed(openrouter, fresh_graphs):
    fake = openrouter([
        turn("", [("bad1", "execute_remediation", '{"incident_id": "INC-2026-091", ')]),
        turn("Stopping."),
    ])
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    assert not [e for e in events if e["type"] == "tool_call"]
    tool_msg = fake.chat_requests[1]["messages"][-1]
    assert tool_msg["role"] == "tool" and tool_msg["tool_call_id"] == "bad1" and "INVALID_ARGUMENTS" in tool_msg["content"]
    assert tools.trace_blast_radius(DEMO_CVE_ID)["total_paths"] == 6


async def test_openrouter_truncated_turn_is_not_executed(openrouter, fresh_graphs):
    fake = openrouter([
        turn("", [("t1", "simulate_remediation", SIM_ARGS)], finish="length"),
        turn("Done."),
    ])
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    assert not [e for e in events if e["type"] == "tool_call"]
    msgs = fake.chat_requests[1]["messages"]
    assert msgs[-2]["role"] == "tool" and msgs[-2]["tool_call_id"] == "t1" and "not executed" in msgs[-2]["content"]
    assert msgs[-1]["role"] == "user"


async def test_openrouter_auth_error_is_reported(openrouter, fresh_graphs):
    openrouter([httpx.Response(401, json={"error": {"code": 401, "message": "No auth credentials found"}})])
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    err = next(e for e in events if e["type"] == "error")
    assert "401" in err["message"] and "OPENROUTER_API_KEY" in err["message"]
    assert events[-1]["type"] == "run_completed"


def test_provider_resolution():
    assert _resolve_provider({}) == "none"
    assert _resolve_provider({"OPENROUTER_API_KEY": "x"}) == "openrouter"
    assert _resolve_provider({"ANTHROPIC_API_KEY": "x"}) == "anthropic"
    assert _resolve_provider({"ANTHROPIC_API_KEY": "x", "OPENROUTER_API_KEY": "y", "AEGIS_LLM_PROVIDER": "openrouter"}) == "openrouter"
    assert orc.is_free_id("openrouter/free") and orc.is_free_id("x/y:free") and not orc.is_free_id("openai/gpt")
