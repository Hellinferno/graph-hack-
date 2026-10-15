"""Agent orchestrator: investigates an incident and remediates it using FalkorDB as the context layer.

Two modes, both of which call graph tools ONLY through the Model Context Protocol (``MCPToolbox``):

* ``deterministic`` — a fixed 5-stage doctrine (anchor -> blast radius -> chokepoint -> simulate -> act) whose
  every decision is read off graph query / algorithm results. Runs without any LLM key.
* ``llm`` — Claude (Anthropic SDK) is given the MCP tool list and the same doctrine as a system prompt and
  chooses which tools to call; the loop streams its reasoning summaries, narrative and tool calls.

``AgentRunner.run`` is an async generator of event dicts (docs/DESIGN.md §5) consumed by the API (SSE) and the
CLI. Every run is persisted as an ``Episode`` in the memory graph.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Literal

from . import graph as g
from . import memory
from .config import settings
from .mcp_client import MCPToolbox, ToolCallResult

log = logging.getLogger("aegis.agent")

Mode = Literal["auto", "llm", "deterministic"]

STAGES: list[tuple[int, str]] = [(1, "anchor"), (2, "blast_radius"), (3, "chokepoint"), (4, "simulate"), (5, "act")]
STAGE_BY_TOOL: dict[str, int] = {
    "recall_similar_incidents": 1, "find_entry_points": 1,
    "trace_blast_radius": 2, "read_graph": 2,
    "rank_service_criticality": 3, "shortest_attack_path": 3, "expand_neighborhood": 3, "detect_service_communities": 3, "find_code_owner": 3,
    "simulate_remediation": 4,
    "execute_remediation": 5, "rollback_remediation": 5, "get_decision_proof": 5,
}
_DROP_KEYS_FOR_LLM = {"cypher", "path", "proof_subgraph"}
_MAX_TOOL_RESULT_CHARS = 30_000
# An alert anchors to a CVE only if the vector match is reasonably close or a full-text keyword matched;
# otherwise the deterministic agent falls back to the CVE the incident is linked to (TRIGGERED_ON).
ANCHOR_MAX_DISTANCE = 0.8
_EXECUTED = ("ACTION_EXECUTED", "PARTIAL")

SYSTEM_PROMPT = """You are AegisGraph, an autonomous security incident responder. Your only source of truth is a FalkorDB
property graph (CVEs -> packages <- functions <- services -> services -> IAM roles -> databases, plus developers and
incidents) that you reach through the MCP tools you have been given. Never guess topology: query it.

Doctrine (follow these stages, calling the tools yourself):
1. ANCHOR - call recall_similar_incidents (reuse proven playbooks) and find_entry_points with the raw alert to
   identify the CVE, affected package and entry services.
2. BLAST RADIUS - call trace_blast_radius for the CVE. "Exposure" = active paths from a service that deploys code
   importing the vulnerable package, through ROUTES_TO hops, to an IAM role that CAN_ACCESS a PII database.
3. CHOKEPOINT - call rank_service_criticality (PageRank = too critical to isolate; betweenness = chokepoint) and,
   if useful, shortest_attack_path / expand_neighborhood / detect_service_communities / read_graph. Choose the
   NON-critical pivot service on the exposed paths with the highest betweenness, and the IAM role it assumes on
   those paths. Never isolate a service whose tier is "critical" - if only critical pivots exist, do not act and
   explain why; route a code-fix PR via find_code_owner instead.
4. SIMULATE - call simulate_remediation (sandbox graph + algo.WCC + critical-flow checks). If safe_to_execute
   is false, reconsider the target or stop.
5. ACT - call execute_remediation with a justification that cites the exposed path count, the betweenness and
   PageRank scores and the sandbox result, then call trace_blast_radius again to verify exposure is 0.

Finish with a 3-6 sentence explanation for the on-call engineer: what was exposed (paths, databases), why this
chokepoint, what the sandbox proved, what was changed, who got the PR, and the audit id. Keep tool arguments
exact (service names, role names and CVE ids come from previous tool results)."""


@dataclass
class _RunContext:
    run_id: str
    incident_id: str
    mode: str
    toolbox: MCPToolbox
    episode_id: str | None
    started: float
    seq: int = 0
    last: ToolCallResult | None = None
    stage_state: dict[int, str] = field(default_factory=dict)
    audit_id: str | None = None
    outcome: str = "NO_ACTION"
    tool_calls: int = 0
    cve_id: str | None = None  # the CVE actually investigated (recorded on the Episode)


def _ev(ctx: _RunContext, type_: str, **fields: Any) -> dict[str, Any]:
    return {"type": type_, "ts": round(time.time(), 3), "run_id": ctx.run_id, **fields}


def _llm_view(value: Any) -> Any:
    """Tool results as the LLM sees them: identical data minus bulky explainability payloads."""
    if isinstance(value, dict):
        return {k: _llm_view(v) for k, v in value.items() if k not in _DROP_KEYS_FOR_LLM}
    if isinstance(value, list):
        return [_llm_view(v) for v in value]
    return value


def rank_candidates(blast: dict[str, Any], betweenness: dict[str, float], pagerank: dict[str, float]) -> list[dict[str, Any]]:
    """Rank remediation targets among the pivot services of the exposed paths.

    coverage = how many exposed paths pass through the service anywhere (not only as pivot). Eligible = not
    critical-tier. Order: eligible first, then coverage desc, betweenness desc, rps asc (cheapest to isolate).
    """
    paths = blast.get("exposed_paths", [])
    coverage: Counter[str] = Counter()
    for p in paths:
        for name in set(p.get("path_nodes", [])):
            coverage[name] += 1
    out = []
    for piv in blast.get("pivot_services", []):
        name = piv["name"]
        critical = piv.get("tier") == "critical"
        out.append({
            "service": name, "tier": piv.get("tier"), "rps": piv.get("rps"), "iam_roles": piv.get("iam_roles", []),
            "coverage": coverage.get(name, 0), "total_paths": len(paths),
            "betweenness": round(float(betweenness.get(name, 0.0)), 4), "pagerank": round(float(pagerank.get(name, 0.0)), 4),
            "eligible": not critical, "reason": "critical-tier service: never isolated" if critical else "",
        })
    out.sort(key=lambda c: (not c["eligible"], -c["coverage"], -c["betweenness"], c["rps"] or 0))
    return out


def sanitize_assistant_content(blocks: list[Any]) -> list[Any]:
    """Prepare a response's content for echoing back (Anthropic server-side fallback semantics).

    After a mid-output fallback, thinking / redacted_thinking / tool_use and other model-internal blocks that
    appear BEFORE the last ``fallback`` block must be omitted; text blocks and everything after the boundary are
    echoed normally. The ``fallback`` block itself is an audit marker and is dropped. Without a fallback the
    content is returned unchanged (append-only history keeps thinking blocks valid).
    """
    boundary = max((i for i, b in enumerate(blocks) if getattr(b, "type", "") == "fallback"), default=-1)
    if boundary < 0:
        return list(blocks)
    kept = []
    for i, b in enumerate(blocks):
        btype = getattr(b, "type", "")
        if btype == "fallback":
            continue
        if i < boundary and btype != "text":
            continue
        kept.append(b)
    return kept


def _tool_payload(res: ToolCallResult | None) -> str:
    """JSON text of a tool result as the model sees it (explainability payloads stripped, size-capped)."""
    payload = json.dumps(_llm_view(res.result), default=str) if res else "{}"
    if len(payload) > _MAX_TOOL_RESULT_CHARS:
        payload = payload[:_MAX_TOOL_RESULT_CHARS] + "... [truncated]"
    return payload


def _path_highlight(paths: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, str]]]:
    nodes: list[str] = []
    edges: list[dict[str, str]] = []
    for p in paths:
        path = p.get("path") or {}
        id_to_name = {n["id"]: n["name"] for n in path.get("nodes", [])}
        for n in path.get("nodes", []):
            if n["name"] not in nodes:
                nodes.append(n["name"])
        for e in path.get("edges", []):
            edge = {"src": id_to_name.get(e["src_id"], str(e["src_id"])), "dst": id_to_name.get(e["dst_id"], str(e["dst_id"])), "type": e["type"]}
            if edge not in edges:
                edges.append(edge)
    return nodes, edges


def _highlights(ctx: _RunContext, name: str, args: dict[str, Any], res: ToolCallResult) -> list[dict[str, Any]]:
    if res.is_error or not isinstance(res.result, dict):
        return []
    out: list[dict[str, Any]] = []
    r = res.result
    if name == "trace_blast_radius" and r.get("exposed_paths"):
        nodes, edges = _path_highlight(r["exposed_paths"])
        out.append(_ev(ctx, "graph_highlight", style="attack", nodes=nodes, edges=edges,
                       label=f"{r['total_paths']} active attack paths to {len(r.get('exposed_databases', []))} PII databases"))
    elif name == "shortest_attack_path" and r.get("found") and r.get("path"):
        nodes, edges = _path_highlight([{"path": r["path"]}])
        out.append(_ev(ctx, "graph_highlight", style="proof", nodes=nodes, edges=edges, label=f"shortest attack path ({r['hop_count']} hops)"))
    elif name == "simulate_remediation":
        flows = [f for f in r.get("critical_flows", []) if f.get("intact")]
        nodes = sorted({f["source"] for f in flows} | {f["target"] for f in flows})
        out.append(_ev(ctx, "graph_highlight", style="chokepoint", nodes=[r.get("bridge_service"), r.get("iam_role")], edges=[],
                       label=f"candidate chokepoint {r.get('bridge_service')} / {r.get('iam_role')}"))
        out.append(_ev(ctx, "graph_highlight", style="safe", nodes=nodes,
                       edges=[{"src": f["source"], "dst": f["target"], "type": "ROUTES_TO"} for f in flows],
                       label="critical flows verified intact in sandbox" if r.get("critical_flows_intact") else "critical flow broken in sandbox"))
    elif name == "execute_remediation" and r.get("status") in _EXECUTED:
        edges = [{"src": m["src"], "dst": m["dst"], "type": m["type"]} for m in r.get("mutations", []) if m.get("kind") == "edge"]
        nodes = [m["name"] for m in r.get("mutations", []) if m.get("kind") == "node"]
        out.append(_ev(ctx, "graph_highlight", style="quarantined", nodes=nodes, edges=edges, label=f"quarantined by audit {r.get('audit_id')}"))
    return out


class AgentRunner:
    def __init__(self, toolbox: MCPToolbox | None = None) -> None:
        self._shared_toolbox = toolbox

    # ------------------------------------------------------------------ public entry point
    async def run(self, incident_id: str, alert_text: str | None = None, mode: Mode = "auto",
                  run_id: str | None = None) -> AsyncIterator[dict[str, Any]]:
        """Investigate (and possibly remediate) an incident. ``run_id`` lets the API keep one id for the run and its events."""
        run_id = run_id or f"run-{uuid.uuid4().hex[:10]}"
        resolved: str = mode if mode != "auto" else ("llm" if settings.llm_configured else "deterministic")
        if resolved == "llm" and not settings.llm_configured:
            yield {"type": "error", "ts": time.time(), "run_id": run_id, "message": "LLM mode requires ANTHROPIC_API_KEY or OPENROUTER_API_KEY; use deterministic mode", "recoverable": False}
            return
        own_toolbox = self._shared_toolbox is None
        toolbox = self._shared_toolbox or MCPToolbox()
        if not toolbox.started:
            await toolbox.start()
        incident = await asyncio.to_thread(self._load_incident, incident_id)
        ctx = _RunContext(run_id=run_id, incident_id=incident_id, mode=resolved, toolbox=toolbox,
                          episode_id=None, started=time.perf_counter())
        try:
            if incident is None:
                yield _ev(ctx, "error", message=f"unknown incident '{incident_id}'", recoverable=False)
                return
            alert = (alert_text or incident.get("raw_alert") or incident.get("title") or "").strip()
            ctx.episode_id = await asyncio.to_thread(memory.start_episode, incident_id, incident.get("cve_id"), resolved)
            yield _ev(ctx, "run_started", incident_id=incident_id, mode=resolved, model=settings.active_llm_model if resolved == "llm" else None,
                      provider=settings.llm_provider if resolved == "llm" else None,
                      tools=[t.name for t in toolbox.list_tools()], incident_title=incident.get("title"), alert_text=alert,
                      episode_id=ctx.episode_id)
            summary = ""
            if resolved == "deterministic":
                async for ev in self._run_deterministic(ctx, alert, incident.get("cve_id")):
                    if ev["type"] == "run_completed":
                        summary = ev["summary"]
                    yield ev
            else:
                async for ev in self._run_llm(ctx, incident, alert):
                    if ev["type"] == "run_completed":
                        summary = ev["summary"]
                    yield ev
            await asyncio.to_thread(memory.finish_episode, ctx.episode_id, ctx.outcome, summary, ctx.cve_id)
        except Exception as exc:  # noqa: BLE001 - a run must always end with an event, never a hung stream
            log.exception("agent run failed")
            ctx.outcome = "ERROR"
            await asyncio.to_thread(memory.finish_episode, ctx.episode_id, "ERROR", f"{type(exc).__name__}: {exc}", ctx.cve_id)
            yield _ev(ctx, "error", message=f"{type(exc).__name__}: {exc}", recoverable=False)
            yield self._completed(ctx, outcome="ERROR", summary=f"run aborted: {exc}")
        finally:
            if own_toolbox:
                await toolbox.stop()

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _load_incident(incident_id: str) -> dict[str, Any] | None:
        rows = g.run_query(
            g.prod_graph(),
            "MATCH (i:Incident {id: $id}) OPTIONAL MATCH (i)-[:TRIGGERED_ON]->(v:Vulnerability) RETURN i, v.id",
            {"id": incident_id}, read_only=True,
        )
        if not rows:
            return None
        return {**rows[0][0]["properties"], "cve_id": rows[0][1]}

    def _stage_events(self, ctx: _RunContext, tool_name: str) -> list[dict[str, Any]]:
        stage = STAGE_BY_TOOL.get(tool_name)
        if stage is None:
            return []
        out = []
        for num, name in STAGES:
            if num < stage and ctx.stage_state.get(num) == "started":
                ctx.stage_state[num] = "completed"
                out.append(_ev(ctx, "stage", stage=num, name=name, status="completed", detail=""))
        if ctx.stage_state.get(stage) is None:
            ctx.stage_state[stage] = "started"
            out.append(_ev(ctx, "stage", stage=stage, name=dict(STAGES)[stage], status="started", detail=tool_name))
        return out

    def _close_stages(self, ctx: _RunContext, skipped_detail: str = "") -> list[dict[str, Any]]:
        out = []
        for num, name in STAGES:
            state = ctx.stage_state.get(num)
            if state == "started":
                ctx.stage_state[num] = "completed"
                out.append(_ev(ctx, "stage", stage=num, name=name, status="completed", detail=""))
            elif state is None:
                ctx.stage_state[num] = "skipped"
                out.append(_ev(ctx, "stage", stage=num, name=name, status="skipped", detail=skipped_detail))
        return out

    async def _tool(self, ctx: _RunContext, name: str, args: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
        """Call one MCP tool; yields stage / tool_call / tool_result / graph_highlight events; result in ctx.last."""
        ctx.seq += 1
        call_id = f"{ctx.run_id}-{ctx.seq}"
        for ev in self._stage_events(ctx, name):
            yield ev
        yield _ev(ctx, "tool_call", call_id=call_id, name=name, args=args, seq=ctx.seq)
        res = await ctx.toolbox.call_tool(name, args)
        ctx.last = res
        ctx.tool_calls += 1
        await asyncio.to_thread(memory.record_tool_call, ctx.episode_id, ctx.seq, name, args, res.result, res.duration_ms, res.is_error)
        yield _ev(ctx, "tool_result", call_id=call_id, name=name, result=res.result, duration_ms=round(res.duration_ms, 2),
                  is_error=res.is_error, server=res.server)
        if not res.is_error and isinstance(res.result, dict):
            r = res.result
            if name in ("trace_blast_radius", "simulate_remediation", "execute_remediation") and args.get("cve_id"):
                ctx.cve_id = str(args["cve_id"])
            if name == "simulate_remediation" and r.get("simulation_id"):
                await asyncio.to_thread(memory.link_simulation, ctx.episode_id, r["simulation_id"])
            if name == "execute_remediation" and r.get("status") in _EXECUTED:
                ctx.audit_id = r.get("audit_id")
                ctx.outcome = "MITIGATED" if r["status"] == "ACTION_EXECUTED" else "PARTIAL"
                if r.get("playbook"):
                    await asyncio.to_thread(memory.link_playbook, ctx.episode_id, r["playbook"])
            if name == "rollback_remediation" and r.get("status") == "ROLLED_BACK" and r.get("audit_id") == ctx.audit_id:
                ctx.audit_id = None  # the run's own action was undone within the run
                ctx.outcome = "NO_ACTION"
        for ev in _highlights(ctx, name, args, res):
            yield ev

    def _completed(self, ctx: _RunContext, outcome: str, summary: str) -> dict[str, Any]:
        ctx.outcome = outcome
        return _ev(ctx, "run_completed", outcome=outcome, summary=summary, audit_id=ctx.audit_id,
                   duration_ms=round((time.perf_counter() - ctx.started) * 1000, 1), tool_call_count=ctx.tool_calls,
                   episode_id=ctx.episode_id, mode=ctx.mode)

    # ------------------------------------------------------------------ deterministic doctrine
    @staticmethod
    def _ok(ctx: _RunContext) -> bool:
        return ctx.last is not None and not ctx.last.is_error and isinstance(ctx.last.result, dict)

    def _failure(self, ctx: _RunContext, name: str) -> list[dict[str, Any]]:
        """A required tool failed: end with ERROR (never a false all-clear)."""
        res = ctx.last
        detail = (res.result.get("error") if res and isinstance(res.result, dict) else None) or "no result"
        return [
            _ev(ctx, "error", message=f"{name} failed: {detail}", recoverable=False),
            *self._close_stages(ctx, f"{name} failed"),
            self._completed(ctx, "ERROR", f"{name} failed, so the investigation stopped without a verdict: {detail}"),
        ]

    async def _run_deterministic(self, ctx: _RunContext, alert: str, incident_cve: str | None = None) -> AsyncIterator[dict[str, Any]]:
        notes: list[str] = []
        # Stage 1: anchor
        async for ev in self._tool(ctx, "find_entry_points", {"alert_text": alert, "top_k": 3}):
            yield ev
        if not self._ok(ctx):
            for ev in self._failure(ctx, "find_entry_points"):
                yield ev
            return
        anchor = ctx.last.result
        matches = anchor.get("matches") or []
        best = matches[0] if matches else None
        strong = best is not None and (
            (best.get("vector_distance") is not None and best["vector_distance"] < ANCHOR_MAX_DISTANCE) or (best.get("fulltext_score") or 0) > 0
        )
        if strong:
            cve_id = best["cve_id"]
        elif incident_cve:
            cve_id = incident_cve
            weak = f"{best['cve_id']} at distance {best.get('vector_distance')}" if best else "no candidate"
            notes.append(f"The alert text did not anchor strongly to any CVE (best: {weak}), so the incident's linked {incident_cve} was investigated.")
        else:
            for ev in self._close_stages(ctx, "no CVE matched the alert"):
                yield ev
            yield self._completed(ctx, "NO_ACTION", "The alert did not match any vulnerability in the graph; nothing to remediate.")
            return
        ctx.cve_id = cve_id
        match = next((m for m in matches if m["cve_id"] == cve_id), None)
        package = ((match or {}).get("affected_packages") or [{}])[0].get("name")
        async for ev in self._tool(ctx, "recall_similar_incidents", {"cve_id": cve_id, "package_name": package}):
            yield ev
        recall = ctx.last.result if self._ok(ctx) else {}  # memory is advisory: continue without it

        # Stage 2: blast radius
        async for ev in self._tool(ctx, "trace_blast_radius", {"cve_id": cve_id, "max_route_hops": 3}):
            yield ev
        if not self._ok(ctx):
            for ev in self._failure(ctx, "trace_blast_radius"):
                yield ev
            return
        blast = ctx.last.result
        paths = blast.get("exposed_paths", [])
        if not paths:
            for ev in self._close_stages(ctx, "no active exposure"):
                yield ev
            yield self._completed(ctx, "NO_ACTION", " ".join(notes + [f"{cve_id} has no active attack path to a PII database; no containment needed."]))
            return

        # Stage 3: chokepoint via graph algorithms
        async for ev in self._tool(ctx, "rank_service_criticality", {}):
            yield ev
        if not self._ok(ctx):
            for ev in self._failure(ctx, "rank_service_criticality"):
                yield ev
            return
        ranks = ctx.last.result
        bw = {s["service"]: s["score"] for s in ranks.get("betweenness", [])}
        pr = {s["service"]: s["score"] for s in ranks.get("pagerank", [])}
        bw_rank = {s["service"]: i + 1 for i, s in enumerate(ranks.get("betweenness", []))}
        candidates = rank_candidates(blast, bw, pr)
        eligible = [c for c in candidates if c["eligible"]]
        async for ev in self._tool(ctx, "find_code_owner", {"cve_id": cve_id}):
            yield ev
        owner = ctx.last.result.get("recommended") if self._ok(ctx) else None
        if not eligible:
            for ev in self._close_stages(ctx, "only critical-tier pivots on the attack paths"):
                yield ev
            yield _ev(ctx, "decision", action="NO_ACTION", bridge_service=None, iam_role=None, sim_passed=None, code_owner=owner,
                      scores={}, candidates=candidates,
                      justification="Every pivot on the exposed paths is a critical-tier service; AegisGraph never isolates those. "
                                    "Routing the dependency fix to the code owner instead.")
            yield self._completed(ctx, "NO_ACTION", f"{len(paths)} exposure paths found for {cve_id} but all pivots are critical-tier; "
                                                   f"PR routed to {owner.get('handle') if owner else 'unknown'} without isolation.")
            return
        chosen = eligible[0]
        bridge = chosen["service"]
        iam_role = Counter(p["iam_role"] for p in paths if p["pivot_service"] == bridge).most_common(1)[0][0]
        yield _ev(ctx, "graph_highlight", style="chokepoint", nodes=[bridge, iam_role], edges=[],
                  label=f"chokepoint: {bridge} on {chosen['coverage']}/{len(paths)} attack paths (betweenness #{bw_rank.get(bridge, '?')})")
        origin = paths[0]["origin_service"]
        async for ev in self._tool(ctx, "shortest_attack_path", {"source_service": origin, "target_database": paths[0]["database"], "max_len": 6}):
            yield ev
        protected = [c for c in candidates if not c["eligible"] and c["betweenness"] >= chosen["betweenness"] * 0.5]
        protected_note = "".join(
            f" {c['service']} (betweenness {c['betweenness']:.2f}, {c['rps']} rps) also carries attack paths but is critical-tier and is protected."
            for c in protected
        )
        playbook_hint = ""
        if recall.get("playbooks"):
            pb = recall["playbooks"][0]
            playbook_hint = f" Memory recalled playbook {pb.get('signature')} (isolate {pb.get('bridge_service')} / quarantine {pb.get('iam_role')})."
        justification = (
            f"{len(paths)} active attack paths from {', '.join(blast.get('origin_services', []))} reach {len(blast.get('exposed_databases', []))} "
            f"PII databases ({', '.join(blast.get('exposed_databases', []))}). {bridge} lies on {chosen['coverage']} of the {len(paths)} paths and ranks "
            f"#{bw_rank.get(bridge, '?')} of {len(bw)} services by betweenness ({chosen['betweenness']:.2f}); it is {chosen['tier']}-tier at {chosen['rps']} rps "
            f"(PageRank {chosen['pagerank']:.3f}).{protected_note} Isolating {bridge} and quarantining {iam_role} severs every path.{playbook_hint}"
        )

        # Stage 4: counterfactual sandbox
        async for ev in self._tool(ctx, "simulate_remediation", {"incident_id": ctx.incident_id, "cve_id": cve_id, "bridge_service": bridge, "iam_role": iam_role}):
            yield ev
        if not self._ok(ctx):
            for ev in self._failure(ctx, "simulate_remediation"):
                yield ev
            return
        sim = ctx.last.result
        safe = bool(sim.get("safe_to_execute"))
        yield _ev(ctx, "decision", action="ISOLATE_BRIDGE_AND_QUARANTINE_ROLE" if safe else "ABORT_UNSAFE", bridge_service=bridge, iam_role=iam_role,
                  justification=justification, scores={"betweenness": bw.get(bridge, 0.0), "pagerank": pr.get(bridge, 0.0)},
                  sim_passed=safe, code_owner=owner, simulation=sim.get("simulation_id"), sandbox_graph=sim.get("sandbox_graph"),
                  candidates=candidates)
        if not safe:
            for ev in self._close_stages(ctx, "sandbox simulation failed"):
                yield ev
            reasons = "; ".join(sim.get("unsafe_reasons") or []) or "the simulation did not pass"
            yield self._completed(ctx, "NO_ACTION", " ".join(notes + [f"Sandbox simulation rejected isolating {bridge} / quarantining {iam_role}: {reasons}."]))
            return

        # Stage 5: act + verify
        async for ev in self._tool(ctx, "execute_remediation", {"incident_id": ctx.incident_id, "cve_id": cve_id, "bridge_service": bridge,
                                                                "iam_role": iam_role, "justification": justification + f" Sandbox {sim.get('sandbox_graph')} proved exposure {sim.get('exposure_before')} -> {sim.get('exposure_after')} with all critical flows intact."}):
            yield ev
        if not self._ok(ctx):
            for ev in self._failure(ctx, "execute_remediation"):
                yield ev
            return
        action = ctx.last.result
        if action.get("status") not in _EXECUTED:
            for ev in self._close_stages(ctx, "execution refused"):
                yield ev
            yield self._completed(ctx, "NO_ACTION", f"execute_remediation did not act ({action.get('status')}): {action.get('reason')}")
            return
        async for ev in self._tool(ctx, "trace_blast_radius", {"cve_id": cve_id, "max_route_hops": 3}):
            yield ev
        verify = ctx.last.result if self._ok(ctx) else {}
        for ev in self._close_stages(ctx):
            yield ev
        owner_handle = action.get("assigned_code_owner", {}).get("handle") if action.get("assigned_code_owner") else "unknown"
        if action["status"] == "PARTIAL":
            yield self._completed(ctx, "PARTIAL", " ".join(notes + [
                f"Partially contained {cve_id}: isolated {bridge} and quarantined {iam_role}, but {action.get('reason')}",
            ]))
            return
        summary = (
            f"Contained {cve_id}: isolated {bridge} and quarantined {iam_role}; exposure {len(paths)} -> {verify.get('total_paths', '?')} active paths "
            f"(sandbox proof {sim.get('simulation_id')}), PR routed to {owner_handle}, audit {action.get('audit_id')}."
        )
        yield self._completed(ctx, "MITIGATED", " ".join(notes + [summary]))

    # ------------------------------------------------------------------ LLM-driven doctrine
    async def _run_llm(self, ctx: _RunContext, incident: dict[str, Any], alert: str) -> AsyncIterator[dict[str, Any]]:
        """Dispatch to the configured LLM provider; both loops share tools, events and guardrails."""
        loop = self._run_openrouter if settings.llm_provider == "openrouter" else self._run_anthropic
        async for ev in loop(ctx, incident, alert):
            yield ev

    @staticmethod
    def _user_prompt(ctx: _RunContext, incident: dict[str, Any], alert: str) -> str:
        return (
            f"Incident {ctx.incident_id}: {incident.get('title')}\nStatus: {incident.get('status')}\nRaw alert: {alert}\n\n"
            "Investigate this incident with the tools and remediate it if, and only if, the sandbox simulation proves it safe."
        )

    def _decision_from_execute(self, ctx: _RunContext, args: dict[str, Any]) -> dict[str, Any] | None:
        res = ctx.last
        if res and not res.is_error and isinstance(res.result, dict) and res.result.get("status") in _EXECUTED:
            r = res.result
            return _ev(ctx, "decision", action="ISOLATE_BRIDGE_AND_QUARANTINE_ROLE", bridge_service=r.get("isolated_bridge"),
                       iam_role=r.get("quarantined_role"), justification=args.get("justification", ""), scores=r.get("scores", {}),
                       sim_passed=True, code_owner=r.get("assigned_code_owner"), simulation=r.get("simulation_id"))
        return None

    def _llm_abort(self, ctx: _RunContext, message: str, summary: str) -> list[dict[str, Any]]:
        """LLM request failed: close open stages and report the state the graph is actually in."""
        outcome = ctx.outcome if ctx.audit_id else "ERROR"
        return [_ev(ctx, "error", message=message, recoverable=False), *self._close_stages(ctx, "LLM request failed"),
                self._completed(ctx, outcome, summary)]

    async def _run_anthropic(self, ctx: _RunContext, incident: dict[str, Any], alert: str) -> AsyncIterator[dict[str, Any]]:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
        tools = [spec.as_anthropic_tool() for spec in ctx.toolbox.list_tools()]
        messages: list[dict[str, Any]] = [{"role": "user", "content": self._user_prompt(ctx, incident, alert)}]
        final_text = ""
        iterations = 0
        truncated_retry = False
        while iterations < settings.max_tool_iterations:
            iterations += 1
            try:
                async with client.beta.messages.stream(
                    model=settings.llm_model,
                    max_tokens=32000,
                    # explicit breakpoint on the static prefix (tools + system) + automatic caching of the growing tail
                    system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
                    cache_control={"type": "ephemeral"},
                    tools=tools,
                    messages=messages,
                    thinking={"type": "adaptive", "display": "summarized"},
                    output_config={"effort": settings.llm_effort},
                    # opt into server-side refusal fallbacks (routes by refusal category, e.g. cyber false positives)
                    betas=["server-side-fallback-2026-07-01"],
                    fallbacks="default",
                ) as stream:
                    turn_text = ""
                    async for event in stream:
                        etype = getattr(event, "type", "")
                        if etype == "content_block_delta":
                            delta = event.delta
                            dtype = getattr(delta, "type", "")
                            if dtype == "thinking_delta" and getattr(delta, "thinking", ""):
                                yield _ev(ctx, "thinking", text=delta.thinking)
                            elif dtype == "text_delta" and getattr(delta, "text", ""):
                                turn_text += delta.text
                                yield _ev(ctx, "assistant_text", text=delta.text)
                    final = await stream.get_final_message()
            except anthropic.AuthenticationError as exc:
                for ev in self._llm_abort(ctx, f"Anthropic authentication failed: {exc.message}", "LLM authentication failed; check ANTHROPIC_API_KEY"):
                    yield ev
                return
            except anthropic.RateLimitError as exc:
                for ev in self._llm_abort(ctx, f"Anthropic rate limit: {exc.message}", "LLM rate limited"):
                    yield ev
                return
            except anthropic.APIStatusError as exc:
                for ev in self._llm_abort(ctx, f"Anthropic API error {exc.status_code}: {exc.message}", f"LLM API error {exc.status_code}"):
                    yield ev
                return
            except anthropic.APIConnectionError as exc:
                for ev in self._llm_abort(ctx, f"cannot reach the Anthropic API: {exc}", "LLM connection error"):
                    yield ev
                return

            if any(getattr(b, "type", "") == "fallback" for b in final.content):
                hops = [f"{b.from_.model} -> {b.to.model}" for b in final.content if getattr(b, "type", "") == "fallback"]
                yield _ev(ctx, "assistant_text", text=f"\n[served by fallback model {final.model} ({', '.join(hops)})]\n")
            content = sanitize_assistant_content(final.content)
            if final.stop_reason == "refusal":
                # never execute tools from a refused turn; the partial output is discarded, not echoed
                details = getattr(final, "stop_details", None)
                for ev in self._llm_abort(ctx, f"model refused ({getattr(details, 'category', None)}): {getattr(details, 'explanation', '') or ''}",
                                          "The model declined to continue, so the investigation ended without a verdict."):
                    yield ev
                return
            messages.append({"role": "assistant", "content": content})
            if turn_text:
                final_text = turn_text
            tool_uses = [b for b in content if getattr(b, "type", "") == "tool_use"]
            if final.stop_reason == "max_tokens":
                if truncated_retry:
                    for ev in self._llm_abort(ctx, "model output truncated twice (max_tokens)", "The model's output was cut off twice in a row."):
                        yield ev
                    return
                truncated_retry = True
                # a truncated tool_use input may be incomplete: never run it, answer it with an error result instead
                retry_blocks: list[dict[str, Any]] = [
                    {"type": "tool_result", "tool_use_id": b.id, "is_error": True,
                     "content": "Your output hit max_tokens before this call was complete; it was not executed. Re-issue it."}
                    for b in tool_uses
                ]
                retry_blocks.append({"type": "text", "text": "Your previous turn was cut off. Continue concisely with the next step."})
                messages.append({"role": "user", "content": retry_blocks})
                continue
            truncated_retry = False
            if final.stop_reason == "pause_turn":
                continue
            if not tool_uses:
                break
            results: list[dict[str, Any]] = []
            for block in tool_uses:
                args = dict(block.input) if isinstance(block.input, dict) else {}
                async for ev in self._tool(ctx, block.name, args):
                    yield ev
                res = ctx.last
                results.append({"type": "tool_result", "tool_use_id": block.id, "content": _tool_payload(res), "is_error": bool(res and res.is_error)})
                if block.name == "execute_remediation":
                    decision = self._decision_from_execute(ctx, args)
                    if decision:
                        yield decision
            messages.append({"role": "user", "content": results})
        else:
            for ev in self._llm_abort(ctx, f"stopped after {settings.max_tool_iterations} tool iterations",
                                      "The model did not finish within the iteration limit."):
                yield ev
            return
        for ev in self._close_stages(ctx, "not reached by the model"):
            yield ev
        outcome = ctx.outcome if ctx.audit_id else ("ERROR" if not final_text and not ctx.tool_calls else "NO_ACTION")
        yield self._completed(ctx, outcome, final_text.strip() or "model finished without a final explanation")

    async def _run_openrouter(self, ctx: _RunContext, incident: dict[str, Any], alert: str) -> AsyncIterator[dict[str, Any]]:
        """Same doctrine on OpenRouter free models (OpenAI-compatible tool calling, one request per model turn)."""
        from . import llm_openrouter as orc

        models = settings.openrouter_models
        tools = orc.tools_from_mcp(ctx.toolbox.list_tools())
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": self._user_prompt(ctx, incident, alert)},
        ]
        final_text = ""
        truncated_retry = False
        served_by: str | None = None
        async with orc.make_client() as client:
            try:
                await orc.ensure_free(client, models)
            except orc.OpenRouterError as exc:
                yield _ev(ctx, "error", message=str(exc), recoverable=False)
                for ev in self._close_stages(ctx, "LLM not started"):
                    yield ev
                yield self._completed(ctx, "ERROR", str(exc))
                return
            iterations = 0
            while iterations < settings.max_tool_iterations:
                iterations += 1
                try:
                    data = await orc.chat(client, messages=messages, tools=tools, models=models,
                                          reasoning_effort=settings.openrouter_reasoning)
                except orc.OpenRouterError as exc:
                    for ev in self._llm_abort(ctx, f"{exc}{orc.error_hint(exc.status)}", "The LLM request failed, so the investigation ended without a verdict."):
                        yield ev
                    return
                choice = data["choices"][0]
                msg = choice.get("message") or {}
                finish = choice.get("finish_reason")
                model_used = data.get("model")
                if model_used and model_used != served_by:
                    served_by = model_used
                    yield _ev(ctx, "assistant_text", text=f"[model: {model_used}]\n")
                if finish in ("content_filter", "error") or msg.get("refusal"):
                    # never run tools from a filtered, refused or failed turn, and never use its text as the verdict
                    reason = msg.get("refusal") or ("the provider reported an error for this turn" if finish == "error" else "the output was filtered")
                    for ev in self._llm_abort(ctx, f"model turn rejected: {reason}", "The model turn was refused or failed, so the investigation ended without a verdict."):
                        yield ev
                    return
                reasoning = msg.get("reasoning")
                if isinstance(reasoning, str) and reasoning.strip():
                    yield _ev(ctx, "thinking", text=reasoning.strip() + "\n")
                content = msg.get("content")
                if isinstance(content, list):  # some providers return content parts
                    content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
                content = content or ""
                if content.strip():
                    final_text = content
                    yield _ev(ctx, "assistant_text", text=content.strip() + "\n")
                truncated = finish == "length"
                calls: list[tuple[dict[str, Any], dict[str, Any] | None, str | None]] = []
                for i, tc in enumerate(msg.get("tool_calls") or []):
                    fn = (tc or {}).get("function") or {}
                    if not fn.get("name"):
                        continue
                    args, error = orc.parse_arguments(fn.get("arguments"))
                    # echo well-formed JSON only: a malformed or truncated argument string would make the next request a 400
                    echoed = "{}" if truncated or error is not None else json.dumps(args)
                    call = {"id": tc.get("id") or f"call_{iterations}_{i}", "type": "function", "function": {"name": fn["name"], "arguments": echoed}}
                    calls.append((call, args, error))
                echo: dict[str, Any] = {"role": "assistant", "content": content}
                if calls:
                    echo["tool_calls"] = [c for c, _, _ in calls]
                if msg.get("reasoning_details"):
                    echo["reasoning_details"] = msg["reasoning_details"]  # OpenRouter asks for these to be passed back unchanged
                messages.append(echo)
                if truncated:
                    if truncated_retry:
                        for ev in self._llm_abort(ctx, "model output truncated twice (length)", "The model's output was cut off twice in a row."):
                            yield ev
                        return
                    truncated_retry = True
                    for call, _, _ in calls:  # possibly incomplete arguments: never run them
                        messages.append({"role": "tool", "tool_call_id": call["id"],
                                         "content": "Your output hit the length limit before this call was complete; it was not executed. Re-issue it."})
                    messages.append({"role": "user", "content": "Your previous turn was cut off. Continue concisely with the next step."})
                    continue
                truncated_retry = False
                if not calls:
                    break
                for call, args, error in calls:
                    if error is not None:
                        messages.append({"role": "tool", "tool_call_id": call["id"],
                                         "content": json.dumps({"error": f"INVALID_ARGUMENTS: {error}; the call was not executed"})})
                        continue
                    async for ev in self._tool(ctx, call["function"]["name"], args):
                        yield ev
                    messages.append({"role": "tool", "tool_call_id": call["id"], "content": _tool_payload(ctx.last)})
                    if call["function"]["name"] == "execute_remediation":
                        decision = self._decision_from_execute(ctx, args)
                        if decision:
                            yield decision
            else:
                for ev in self._llm_abort(ctx, f"stopped after {settings.max_tool_iterations} model turns", "The model did not finish within the turn limit."):
                    yield ev
                return
        for ev in self._close_stages(ctx, "not reached by the model"):
            yield ev
        outcome = ctx.outcome if ctx.audit_id else ("ERROR" if not final_text and not ctx.tool_calls else "NO_ACTION")
        yield self._completed(ctx, outcome, final_text.strip() or "model finished without a final explanation")
