"""MCP client side: spawns the AegisGraph MCP server (and optionally the official FalkorDB MCP server) over
stdio and exposes tool discovery + invocation to the agent and the API.

The agent never imports ``tools.py`` directly: every graph operation goes through ``tools/list`` and
``tools/call`` so tool selection is genuinely mediated by the Model Context Protocol.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import get_default_environment, stdio_client

from .config import BACKEND_DIR, PROJECT_ROOT, settings

log = logging.getLogger("aegis.mcp_client")

OFFICIAL_SERVER_BLOCKED_TOOLS = {"delete_graph", "query_graph"}  # query_graph_readonly stays available
FALKORDB_MCP_SCRIPT = PROJECT_ROOT / "mcp" / "falkordb-mcpserver" / "node_modules" / "@falkordb" / "mcpserver" / "dist" / "index.js"


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    server: str

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema, "server": self.server}

    def as_anthropic_tool(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}


@dataclass
class ToolCallResult:
    name: str
    args: dict[str, Any]
    result: Any
    is_error: bool
    duration_ms: float
    server: str
    raw_text: str = ""

    def as_json(self) -> str:
        return json.dumps(self.result, default=str)


@dataclass
class _ServerHandle:
    name: str
    params: StdioServerParameters
    session: ClientSession | None = None
    tools: list[ToolSpec] = field(default_factory=list)


class MCPToolbox:
    """Owns the MCP server subprocesses for the lifetime of an agent run / API process."""

    def __init__(self, include_falkordb_server: bool | None = None) -> None:
        self._stack: AsyncExitStack | None = None
        self._servers: list[_ServerHandle] = []
        self._tool_index: dict[str, tuple[_ServerHandle, ToolSpec]] = {}
        self.include_falkordb_server = settings.enable_falkordb_mcp if include_falkordb_server is None else include_falkordb_server
        self.started = False
        # set when a transport failure shows a server subprocess died; the owner should stop() and start a new box
        self.dead = False

    # ---- lifecycle -------------------------------------------------------------------
    @staticmethod
    def aegis_server_params() -> StdioServerParameters:
        env = {**get_default_environment(), **settings.env_for_subprocess()}
        return StdioServerParameters(command=settings.mcp_python, args=["-m", "aegis.mcp_server"], cwd=str(BACKEND_DIR), env=env)

    @staticmethod
    def falkordb_server_params() -> StdioServerParameters | None:
        if not FALKORDB_MCP_SCRIPT.exists():
            log.warning("official FalkorDB MCP server not installed at %s (run npm install in mcp/falkordb-mcpserver)", FALKORDB_MCP_SCRIPT)
            return None
        env = {**get_default_environment(), "FALKORDB_HOST": settings.falkordb_host, "FALKORDB_PORT": str(settings.falkordb_port)}
        if settings.falkordb_username:
            env["FALKORDB_USERNAME"] = settings.falkordb_username
        if settings.falkordb_password:
            env["FALKORDB_PASSWORD"] = settings.falkordb_password
        # strict read-only: query_graph defaults to GRAPH.RO_QUERY and refuses writes, delete_graph is refused.
        # Every production change must go through execute_remediation's guardrails and audit trail.
        env["FALKORDB_DEFAULT_READONLY"] = "true"
        env["FALKORDB_STRICT_READONLY"] = "true"
        return StdioServerParameters(command="node", args=[str(FALKORDB_MCP_SCRIPT)], env=env)

    async def start(self) -> "MCPToolbox":
        if self.started:
            return self
        self._stack = AsyncExitStack()
        await self._stack.__aenter__()
        handles = [_ServerHandle("aegisgraph", self.aegis_server_params())]
        if self.include_falkordb_server:
            params = self.falkordb_server_params()
            if params is not None:
                handles.append(_ServerHandle("falkordb", params))
        for handle in handles:
            try:
                read, write = await self._stack.enter_async_context(stdio_client(handle.params, errlog=sys.stderr))
                session = await self._stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                listed = await session.list_tools()
                handle.session = session
                for t in listed.tools:
                    if handle.name == "falkordb" and t.name in OFFICIAL_SERVER_BLOCKED_TOOLS:
                        log.info("not exposing %s from the official FalkorDB MCP server (writes bypass the guardrails)", t.name)
                        continue
                    spec = ToolSpec(name=t.name, description=t.description or t.name, input_schema=dict(t.input_schema or {}), server=handle.name)
                    if spec.name in self._tool_index:
                        log.warning("tool name collision: %s from %s shadowed by %s", spec.name, handle.name, self._tool_index[spec.name][0].name)
                        continue
                    handle.tools.append(spec)
                    self._tool_index[spec.name] = (handle, spec)
                self._servers.append(handle)
                log.info("MCP server '%s' ready with %d tools", handle.name, len(handle.tools))
            except Exception:
                if handle.name == "aegisgraph":
                    await self.stop()
                    raise
                log.exception("optional MCP server '%s' failed to start; continuing without it", handle.name)
        self.started = True
        return self

    async def stop(self) -> None:
        if self._stack is not None:
            try:
                await self._stack.aclose()
            except Exception as exc:  # noqa: BLE001 - subprocess teardown must never mask the real error
                log.warning("error while closing MCP servers: %s", exc)
        self._stack = None
        self._servers = []
        self._tool_index = {}
        self.started = False

    async def __aenter__(self) -> "MCPToolbox":
        return await self.start()

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    # ---- discovery + invocation -------------------------------------------------------
    @property
    def servers(self) -> list[str]:
        return [h.name for h in self._servers]

    def list_tools(self) -> list[ToolSpec]:
        return [spec for _, spec in self._tool_index.values()]

    def has_tool(self, name: str) -> bool:
        return name in self._tool_index

    async def call_tool(self, name: str, args: dict[str, Any] | None = None) -> ToolCallResult:
        if name not in self._tool_index:
            return ToolCallResult(name=name, args=args or {}, result={"error": f"unknown tool '{name}'"}, is_error=True, duration_ms=0.0, server="")
        handle, spec = self._tool_index[name]
        assert handle.session is not None
        t0 = time.perf_counter()
        try:
            res = await handle.session.call_tool(name, args or {})
        except Exception as exc:  # noqa: BLE001 - transport failures become error results for the agent
            # tool failures come back as is_error results, so an exception here means the connection is gone
            self.dead = True
            log.error("MCP server '%s' failed during %s: %s", handle.name, name, exc)
            return ToolCallResult(name=name, args=args or {}, result={"error": f"{type(exc).__name__}: {exc}"}, is_error=True,
                                  duration_ms=(time.perf_counter() - t0) * 1000, server=handle.name)
        duration = (time.perf_counter() - t0) * 1000
        texts = [c.text for c in (getattr(res, "content", None) or []) if getattr(c, "type", "") == "text"]
        raw_text = "\n".join(texts)
        is_error = bool(getattr(res, "is_error", False))
        structured = getattr(res, "structured_content", None)
        if is_error:
            result: Any = {"error": raw_text or "tool error"}
        elif isinstance(structured, dict) and structured:
            result = structured.get("result", structured) if set(structured.keys()) == {"result"} else structured
        else:
            try:
                result = json.loads(raw_text) if raw_text else {}
            except json.JSONDecodeError:
                result = {"text": raw_text}
        return ToolCallResult(name=name, args=args or {}, result=result, is_error=is_error, duration_ms=duration, server=handle.name, raw_text=raw_text)


async def quick_call(name: str, args: dict[str, Any] | None = None) -> ToolCallResult:
    """Convenience for scripts/tests: spawn the server, call one tool, tear down."""
    async with MCPToolbox(include_falkordb_server=False) as box:
        return await box.call_tool(name, args)
