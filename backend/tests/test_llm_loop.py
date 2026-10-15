"""LLM-mode orchestration tests with a scripted stand-in for ``anthropic.AsyncAnthropic``.

No API key is used: the fake client replays a fixed sequence of model turns (thinking + text + tool_use blocks) so
the test exercises the real loop around it - MCP tool execution on live FalkorDB, tool_result wiring, event
emission, fallback-block sanitisation and max_tokens handling. The real API contract is in docs/DESIGN.md §1.4.
"""
from __future__ import annotations

import copy
import dataclasses
import json
from types import SimpleNamespace
from typing import Any

import anthropic
import pytest

from aegis import agent as agent_mod
from aegis import tools
from aegis.agent import AgentRunner, sanitize_assistant_content
from aegis.seed import DEMO_CVE_ID, DEMO_INCIDENT_ID


def text(t: str) -> SimpleNamespace:
    return SimpleNamespace(type="text", text=t)


def thinking(t: str) -> SimpleNamespace:
    return SimpleNamespace(type="thinking", thinking=t, signature="sig")


def tool_use(id_: str, name: str, args: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", id=id_, name=name, input=args)


def fallback(src: str, dst: str) -> SimpleNamespace:
    return SimpleNamespace(type="fallback", from_=SimpleNamespace(model=src), to=SimpleNamespace(model=dst))


class _Stream:
    def __init__(self, turn: dict[str, Any]) -> None:
        self.turn = turn

    async def __aenter__(self) -> "_Stream":
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    def __aiter__(self):
        async def gen():
            for block in self.turn["content"]:
                if block.type == "thinking":
                    yield SimpleNamespace(type="content_block_delta", delta=SimpleNamespace(type="thinking_delta", thinking=block.thinking))
                elif block.type == "text":
                    yield SimpleNamespace(type="content_block_delta", delta=SimpleNamespace(type="text_delta", text=block.text))
        return gen()

    async def get_final_message(self) -> SimpleNamespace:
        return SimpleNamespace(content=self.turn["content"], stop_reason=self.turn["stop_reason"],
                               model=self.turn.get("model", "claude-opus-5-5"), stop_details=self.turn.get("stop_details"))


class FakeAsyncAnthropic:
    """Replays ``script`` (one dict per model turn) and records every request."""

    script: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []

    def __init__(self, api_key: str | None = None) -> None:
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self._stream))

    def _stream(self, **kwargs: Any) -> _Stream:
        FakeAsyncAnthropic.requests.append(copy.deepcopy({k: v for k, v in kwargs.items() if k != "tools"}) | {"tools": kwargs["tools"]})
        return _Stream(FakeAsyncAnthropic.script[len(FakeAsyncAnthropic.requests) - 1])


@pytest.fixture
def fake_llm(monkeypatch):
    monkeypatch.setattr(anthropic, "AsyncAnthropic", FakeAsyncAnthropic)
    monkeypatch.setattr(agent_mod, "settings", dataclasses.replace(agent_mod.settings, anthropic_api_key="sk-test-not-used", llm_provider="anthropic"))
    FakeAsyncAnthropic.requests = []
    yield FakeAsyncAnthropic


JUSTIFICATION = ("6 active paths reach 3 PII databases and all pass through legacy-billing-bridge, the top betweenness "
                 "chokepoint (6.0); payment-orchestrator is critical-tier; sandbox proved exposure 6 -> 0.")


def doctrine_script() -> list[dict[str, Any]]:
    return [
        {"content": [thinking("Anchor the alert first."), text("Anchoring the alert. "),
                     tool_use("t1", "find_entry_points", {"alert_text": "forged JWT bearer tokens accepted; jwt-crypto-core bypass"})],
         "stop_reason": "tool_use"},
        {"content": [text("Tracing exposure. "), tool_use("t2", "trace_blast_radius", {"cve_id": DEMO_CVE_ID})], "stop_reason": "tool_use"},
        {"content": [tool_use("t3", "rank_service_criticality", {}), tool_use("t4", "find_code_owner", {"cve_id": DEMO_CVE_ID})],
         "stop_reason": "tool_use"},
        {"content": [tool_use("t5", "simulate_remediation", {"incident_id": DEMO_INCIDENT_ID, "cve_id": DEMO_CVE_ID,
                                                              "bridge_service": "legacy-billing-bridge", "iam_role": "LegacyBillingBridgeAdmin"})],
         "stop_reason": "tool_use"},
        {"content": [tool_use("t6", "execute_remediation", {"incident_id": DEMO_INCIDENT_ID, "cve_id": DEMO_CVE_ID,
                                                             "bridge_service": "legacy-billing-bridge", "iam_role": "LegacyBillingBridgeAdmin",
                                                             "justification": JUSTIFICATION})],
         "stop_reason": "tool_use"},
        {"content": [tool_use("t7", "trace_blast_radius", {"cve_id": DEMO_CVE_ID})], "stop_reason": "tool_use"},
        {"content": [text("Contained CVE-2026-8841: exposure 6 -> 0; PR routed to @aarav-sec.")], "stop_reason": "end_turn"},
    ]


async def test_llm_loop_drives_mcp_tools_and_closes_the_loop(fake_llm, fresh_graphs):
    fake_llm.script = doctrine_script()
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    types = [e["type"] for e in events]
    assert types[0] == "run_started" and events[0]["mode"] == "llm" and events[0]["model"] == "claude-opus-5-5"
    assert "error" not in types, [e for e in events if e["type"] == "error"]
    assert any(e["type"] == "thinking" for e in events) and any(e["type"] == "assistant_text" for e in events)
    assert [e["name"] for e in events if e["type"] == "tool_call"] == [
        "find_entry_points", "trace_blast_radius", "rank_service_criticality", "find_code_owner",
        "simulate_remediation", "execute_remediation", "trace_blast_radius"]
    decision = next(e for e in events if e["type"] == "decision")
    assert decision["bridge_service"] == "legacy-billing-bridge" and decision["sim_passed"] is True
    done = events[-1]
    assert done["type"] == "run_completed" and done["outcome"] == "MITIGATED" and done["audit_id"]
    assert done["summary"].startswith("Contained CVE-2026-8841")
    assert tools.trace_blast_radius(DEMO_CVE_ID)["total_paths"] == 0

    reqs = fake_llm.requests
    assert len(reqs) == 7
    first = reqs[0]
    assert first["model"] == "claude-opus-5-5" and first["thinking"] == {"type": "adaptive", "display": "summarized"}
    assert first["betas"] == ["server-side-fallback-2026-07-01"] and first["fallbacks"] == "default"
    assert first["output_config"]["effort"] in {"low", "medium", "high", "xhigh", "max"}
    assert "tool_choice" not in first  # forced tool use is rejected on this model family
    assert {t["name"] for t in first["tools"]} == set(tools.TOOL_REGISTRY)
    assert all(set(t) == {"name", "description", "input_schema"} for t in first["tools"])
    # turn 3 answered both parallel tool calls in ONE user message, in order, with matching ids
    parallel = reqs[3]["messages"][-1]
    assert parallel["role"] == "user" and [b["tool_use_id"] for b in parallel["content"]] == ["t3", "t4"]
    payload = json.loads(parallel["content"][0]["content"])
    assert "betweenness" in payload and "cypher" not in payload  # bulky explainability payload stays out of the prompt
    # history is append-only: the first assistant turn is echoed unchanged (thinking block included)
    assert [b.type for b in reqs[1]["messages"][1]["content"]] == ["thinking", "text", "tool_use"]


async def test_llm_truncated_tool_call_is_not_executed(fake_llm, fresh_graphs):
    fake_llm.script = [
        {"content": [tool_use("x1", "execute_remediation", {"incident_id": DEMO_INCIDENT_ID})], "stop_reason": "max_tokens"},
        {"content": [text("Stopping: no simulation has been run.")], "stop_reason": "end_turn"},
    ]
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    assert not [e for e in events if e["type"] == "tool_call"]
    retry = fake_llm.requests[1]["messages"][-1]["content"]
    assert retry[0] == {"type": "tool_result", "tool_use_id": "x1", "is_error": True,
                        "content": "Your output hit max_tokens before this call was complete; it was not executed. Re-issue it."}
    assert retry[-1]["type"] == "text"
    assert events[-1]["outcome"] == "NO_ACTION"
    assert tools.trace_blast_radius(DEMO_CVE_ID)["total_paths"] == 6


async def test_llm_refusal_never_runs_tools(fake_llm, fresh_graphs):
    fake_llm.script = [{"content": [tool_use("r1", "trace_blast_radius", {"cve_id": DEMO_CVE_ID})], "stop_reason": "refusal",
                        "stop_details": SimpleNamespace(category="cyber", explanation="declined")}]
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    assert not [e for e in events if e["type"] == "tool_call"]
    assert any(e["type"] == "error" and "refused (cyber)" in e["message"] for e in events)
    assert events[-1]["type"] == "run_completed"


async def test_llm_fallback_turn_is_sanitised_before_echo(fake_llm, fresh_graphs):
    fake_llm.script = [
        {"content": [thinking("partial"), text("Partial answer "), tool_use("dropped", "read_graph", {"cypher": "MATCH (n) RETURN n"}),
                     fallback("claude-opus-5-5", "claude-opus-4-8"), text("continuing. "),
                     tool_use("kept", "trace_blast_radius", {"cve_id": DEMO_CVE_ID})],
         "stop_reason": "tool_use", "model": "claude-opus-4-8"},
        {"content": [text("Done.")], "stop_reason": "end_turn", "model": "claude-opus-4-8"},
    ]
    events = [ev async for ev in AgentRunner().run(DEMO_INCIDENT_ID, None, "llm")]
    assert [e["name"] for e in events if e["type"] == "tool_call"] == ["trace_blast_radius"]
    echoed = fake_llm.requests[1]["messages"][1]["content"]
    assert [b.type for b in echoed] == ["text", "text", "tool_use"] and echoed[-1].id == "kept"
    assert [b["tool_use_id"] for b in fake_llm.requests[1]["messages"][2]["content"]] == ["kept"]
    assert any(e["type"] == "assistant_text" and "fallback model claude-opus-4-8" in e["text"] for e in events)


def test_sanitize_is_identity_without_fallback():
    blocks = [thinking("a"), text("b"), tool_use("c", "x", {})]
    assert sanitize_assistant_content(blocks) == blocks
