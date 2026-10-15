"""Command-line entry points: ``python -m aegis <command>`` (run from backend/).

  seed                       rebuild the demo graphs
  mcp                        start the AegisGraph MCP server on stdio
  tools                      list the tools discovered through MCP
  run INCIDENT [--mode m]    investigate + remediate an incident, streaming events to the terminal
  api [--port N] [--reload]  start the FastAPI backend
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from typing import Any

from .config import settings


def _print_event(ev: dict[str, Any]) -> None:
    t = ev["type"]
    if t == "run_started":
        print(f"▶ run {ev['run_id']} mode={ev['mode']} incident={ev['incident_id']} tools={len(ev['tools'])}")
    elif t == "stage":
        print(f"  [stage {ev['stage']} {ev['name']}] {ev['status']} {ev.get('detail') or ''}".rstrip())
    elif t == "tool_call":
        print(f"  → {ev['name']}({json.dumps(ev['args'])[:160]})")
    elif t == "tool_result":
        r = ev["result"]
        digest = json.dumps({k: v for k, v in r.items() if k not in ('cypher',)} if isinstance(r, dict) else r, default=str)
        print(f"  ← {ev['name']} {'ERROR ' if ev['is_error'] else ''}{ev['duration_ms']}ms {digest[:220]}")
    elif t == "graph_highlight":
        print(f"  ✦ highlight {ev['style']}: {ev.get('label')}")
    elif t == "decision":
        print(f"  ★ decision {ev['action']} bridge={ev.get('bridge_service')} role={ev.get('iam_role')} sim_passed={ev.get('sim_passed')}")
        print(f"    {ev.get('justification')}")
    elif t == "thinking":
        sys.stdout.write(ev["text"])
    elif t == "assistant_text":
        sys.stdout.write(ev["text"])
    elif t == "error":
        print(f"  ✖ error: {ev['message']}")
    elif t == "run_completed":
        print(f"■ completed outcome={ev['outcome']} audit={ev.get('audit_id')} tool_calls={ev['tool_call_count']} in {ev['duration_ms']}ms")
        print(f"  {ev['summary']}")


async def _cmd_run(args: argparse.Namespace) -> int:
    from .agent import AgentRunner

    runner = AgentRunner()
    outcome = 1
    async for ev in runner.run(args.incident, args.alert, args.mode):
        if args.json:
            print(json.dumps(ev, default=str))
        else:
            _print_event(ev)
        if ev["type"] == "run_completed":
            outcome = 0 if ev["outcome"] in ("MITIGATED", "NO_ACTION") else 1
    return outcome


async def _cmd_tools() -> int:
    from .mcp_client import MCPToolbox

    async with MCPToolbox() as box:
        for spec in box.list_tools():
            props = ", ".join((spec.input_schema.get("properties") or {}).keys())
            print(f"{spec.server:10s} {spec.name}({props})")
            print(f"           {spec.description.strip().splitlines()[0][:140]}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p_seed = sub.add_parser("seed", help="rebuild the demo graphs (the agent's memory graph is kept)")
    p_seed.add_argument("--reset-memory", action="store_true", help="also wipe the memory graph (episodes, playbooks)")
    sub.add_parser("mcp", help="start the MCP server (stdio)")
    sub.add_parser("tools", help="list tools discovered through MCP")
    p_run = sub.add_parser("run", help="investigate and remediate an incident")
    p_run.add_argument("incident")
    p_run.add_argument("--mode", choices=["auto", "llm", "deterministic"], default="auto")
    p_run.add_argument("--alert", default=None, help="override the alert text")
    p_run.add_argument("--json", action="store_true", help="print raw JSON events")
    p_api = sub.add_parser("api", help="start the FastAPI backend")
    p_api.add_argument("--port", type=int, default=settings.api_port)
    p_api.add_argument("--host", default="127.0.0.1")
    p_api.add_argument("--reload", action="store_true")
    args = parser.parse_args(argv)
    # the run printer uses symbols; never crash when stdout is a pipe or file with a legacy Windows code page
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8", errors="replace")

    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if args.command == "seed":
        from .seed import seed_all

        print(json.dumps(seed_all(reset_memory=args.reset_memory), indent=2))
        return 0
    if args.command == "mcp":
        from .mcp_server import main as mcp_main

        mcp_main()
        return 0
    if args.command == "tools":
        return asyncio.run(_cmd_tools())
    if args.command == "run":
        return asyncio.run(_cmd_run(args))
    if args.command == "api":
        import uvicorn

        uvicorn.run("aegis.api:app", host=args.host, port=args.port, reload=args.reload, log_level="info")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
