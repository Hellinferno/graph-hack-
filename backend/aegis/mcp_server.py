"""AegisGraph MCP server: exposes the FalkorDB graph tools over the Model Context Protocol (stdio).

Run with ``python -m aegis.mcp_server`` (or ``python -m aegis mcp``). Any MCP client (the AegisGraph agent,
Claude Desktop, an IDE) can discover the tools with ``tools/list`` and call them with ``tools/call``.
stdout is reserved for the protocol, so all logging goes to stderr.
"""
from __future__ import annotations

import inspect
import logging
import sys

from mcp.server.mcpserver import MCPServer

from . import tools

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("aegis.mcp_server")

INSTRUCTIONS = """AegisGraph tools operate on a FalkorDB property graph that links CVEs, packages, functions,
production services, IAM roles, PII databases, developers and incidents. Investigate in this order:
1) recall_similar_incidents and find_entry_points to anchor the alert, 2) trace_blast_radius to enumerate active
attack paths to PII data, 3) rank_service_criticality (+ shortest_attack_path / expand_neighborhood) to pick the
non-critical chokepoint to isolate, 4) simulate_remediation in a sandbox graph (mandatory), 5) execute_remediation
only when the simulation is safe, then trace_blast_radius again to verify. Never isolate critical-tier services."""


def build_server() -> MCPServer:
    server = MCPServer(name="aegisgraph", instructions=INSTRUCTIONS, version="0.1.0")
    for name, fn in tools.TOOL_REGISTRY.items():
        server.tool(name=name, description=inspect.cleandoc(fn.__doc__ or name))(fn)
    return server


server = build_server()


def main() -> None:
    log.info("starting AegisGraph MCP server (%d tools, graph=%s)", len(tools.TOOL_REGISTRY), tools.settings.prod_graph_name)
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
