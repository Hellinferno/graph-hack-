from __future__ import annotations

from aegis.mcp_client import MCPToolbox
from aegis.seed import DEMO_CVE_ID
from aegis.tools import TOOL_REGISTRY


async def test_mcp_server_exposes_all_tools_over_stdio():
    async with MCPToolbox(include_falkordb_server=False) as box:
        names = {t.name for t in box.list_tools()}
        assert names == set(TOOL_REGISTRY)
        assert box.servers == ["aegisgraph"]
        spec = next(t for t in box.list_tools() if t.name == "trace_blast_radius")
        assert spec.input_schema["properties"]["cve_id"]["type"] == "string"
        assert "required" in spec.input_schema and "cve_id" in spec.input_schema["required"]
        assert "blast radius" in spec.description.lower()
        anthropic_tool = spec.as_anthropic_tool()
        assert set(anthropic_tool) == {"name", "description", "input_schema"}


async def test_mcp_tool_call_roundtrip_and_errors():
    async with MCPToolbox(include_falkordb_server=False) as box:
        res = await box.call_tool("trace_blast_radius", {"cve_id": DEMO_CVE_ID, "max_route_hops": 3})
        assert not res.is_error and res.server == "aegisgraph"
        assert res.result["total_paths"] == 6 and res.result["cypher"]
        bad = await box.call_tool("trace_blast_radius", {"cve_id": "CVE-0000-0000"})
        assert bad.is_error and "unknown vulnerability" in bad.result["error"]
        write = await box.call_tool("read_graph", {"cypher": "MATCH (s:Service) SET s.status = 'PWNED' RETURN s"})
        assert write.is_error
        unknown = await box.call_tool("no_such_tool", {})
        assert unknown.is_error and "unknown tool" in unknown.result["error"]
