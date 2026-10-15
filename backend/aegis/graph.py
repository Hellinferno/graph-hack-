"""FalkorDB connection and graph helpers.

Verified against FalkorDB 6.0.2 (docker falkordb/falkordb:latest) with falkordb-py 1.7.1:
- ``Graph.query`` sends GRAPH.QUERY (read/write); ``Graph.ro_query`` sends GRAPH.RO_QUERY and the server
  rejects any write inside it ("graph.RO_QUERY is to be executed only on read-only queries").
- ``Graph.delete`` raises ``ResponseError('Invalid graph operation on empty key')`` if the graph does not exist.
- ``GRAPH.COPY src dst`` clones nodes, edges AND indexes; it fails with "destination key already exists".
- Query results contain ``falkordb.node.Node`` (``.id``, ``.labels``, ``.properties``),
  ``falkordb.edge.Edge`` (``.id``, ``.relation``, ``.src_node``, ``.dest_node``, ``.properties``) and
  ``falkordb.path.Path`` (``.nodes()``, ``.edges()``) objects; vector properties come back as plain lists.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Any

from falkordb import FalkorDB, Graph
from falkordb.edge import Edge
from falkordb.node import Node
from falkordb.path import Path
from redis.exceptions import ResponseError

from .config import settings

_lock = threading.Lock()
_db: FalkorDB | None = None


def get_db() -> FalkorDB:
    """Process-wide FalkorDB client (thread-safe lazy init)."""
    global _db
    with _lock:
        if _db is None:
            _db = FalkorDB(
                host=settings.falkordb_host,
                port=settings.falkordb_port,
                username=settings.falkordb_username,
                password=settings.falkordb_password,
            )
        return _db


def reset_db() -> None:
    """Drop the cached client (used by tests when settings change)."""
    global _db
    with _lock:
        _db = None


def ping() -> bool:
    try:
        return bool(get_db().connection.ping())
    except Exception:  # noqa: BLE001 - any failure means FalkorDB is unreachable
        return False


def prod_graph() -> Graph:
    return get_db().select_graph(settings.prod_graph_name)


def memory_graph() -> Graph:
    return get_db().select_graph(settings.memory_graph_name)


def sim_graph_name(incident_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", incident_id)
    return f"{settings.graph_prefix}sim_{safe}"


def list_graphs() -> list[str]:
    return [str(g) for g in get_db().list_graphs()]


def graph_exists(name: str) -> bool:
    return name in list_graphs()


def delete_graph_if_exists(name: str) -> bool:
    """Delete a graph; return True if it existed."""
    try:
        get_db().select_graph(name).delete()
        return True
    except ResponseError as exc:
        if "empty key" in str(exc).lower():
            return False
        raise


def copy_graph(src: str, dst: str) -> None:
    """Clone ``src`` into ``dst`` with GRAPH.COPY (replacing ``dst`` if it already exists)."""
    delete_graph_if_exists(dst)
    get_db().connection.execute_command("GRAPH.COPY", src, dst)


# --------------------------------------------------------------------------------------
# Serialisation of FalkorDB result values into plain JSON-able structures
# --------------------------------------------------------------------------------------


def node_name(node: Node) -> str:
    props = node.properties or {}
    return str(props.get("name") or props.get("id") or props.get("arn") or node.id)


def serialize_node(node: Node) -> dict[str, Any]:
    props = {k: serialize(v) for k, v in (node.properties or {}).items() if k != "embedding"}
    return {"id": node.id, "labels": list(node.labels or []), "name": node_name(node), "properties": props}


def serialize_edge(edge: Edge) -> dict[str, Any]:
    return {
        "id": edge.id,
        "type": edge.relation,
        "src_id": edge.src_node,
        "dst_id": edge.dest_node,
        "properties": {k: serialize(v) for k, v in (edge.properties or {}).items()},
    }


def serialize_path(path: Path) -> dict[str, Any]:
    return {"nodes": [serialize_node(n) for n in path.nodes()], "edges": [serialize_edge(e) for e in path.edges()]}


def serialize(value: Any) -> Any:
    if isinstance(value, Node):
        return serialize_node(value)
    if isinstance(value, Edge):
        return serialize_edge(value)
    if isinstance(value, Path):
        return serialize_path(value)
    if isinstance(value, dict):
        return {str(k): serialize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [serialize(v) for v in value]
    return value


@dataclass
class CypherTrace:
    """One executed query, kept so every tool result can show the exact Cypher that produced it."""

    cypher: str
    params: dict[str, Any] = field(default_factory=dict)
    run_time_ms: float = 0.0
    row_count: int = 0
    graph: str = ""

    def as_dict(self) -> dict[str, Any]:
        params = {
            k: (v if not isinstance(v, list) or len(v) <= 8 else f"<list[{len(v)}]>") for k, v in self.params.items()
        }
        return {
            "graph": self.graph,
            "cypher": self.cypher.strip(),
            "params": params,
            "run_time_ms": round(self.run_time_ms, 3),
            "rows": self.row_count,
        }


def run_query(
    graph: Graph,
    cypher: str,
    params: dict[str, Any] | None = None,
    *,
    read_only: bool = False,
    trace: list[CypherTrace] | None = None,
) -> list[list[Any]]:
    """Run a query and return serialised rows; optionally append a CypherTrace to ``trace``."""
    params = params or {}
    result = graph.ro_query(cypher, params=params) if read_only else graph.query(cypher, params=params)
    rows = [[serialize(v) for v in row] for row in (result.result_set or [])]
    if trace is not None:
        trace.append(
            CypherTrace(
                cypher=cypher,
                params=params,
                run_time_ms=float(result.run_time_ms or 0.0),
                row_count=len(rows),
                graph=graph.name,
            )
        )
    return rows


def graph_snapshot(graph: Graph) -> dict[str, Any]:
    """Whole-graph export (nodes + edges) for the visualiser. Embeddings are stripped."""
    nodes = run_query(graph, "MATCH (n) RETURN n", read_only=True)
    edges = run_query(graph, "MATCH ()-[r]->() RETURN r", read_only=True)
    return {"graph": graph.name, "nodes": [row[0] for row in nodes], "edges": [row[0] for row in edges]}


def label_counts(graph: Graph) -> dict[str, int]:
    rows = run_query(graph, "MATCH (n) UNWIND labels(n) AS l RETURN l, count(*) ORDER BY l", read_only=True)
    return {row[0]: int(row[1]) for row in rows}
