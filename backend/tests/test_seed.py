from __future__ import annotations

from aegis import graph as g
from aegis.config import settings
from aegis.seed import DEMO_CVE_ID, DEMO_INCIDENT_ID, HISTORICAL_INCIDENT_ID


def test_prod_label_counts():
    counts = g.label_counts(g.prod_graph())
    assert counts == {
        "ActionAudit": 1, "Database": 5, "Developer": 5, "Function": 12, "IAMRole": 4, "Incident": 2,
        "Package": 6, "Service": 10, "Vulnerability": 4,
    }


def test_prod_edge_counts():
    rows = g.run_query(g.prod_graph(), "MATCH ()-[r]->() RETURN type(r), count(r) ORDER BY type(r)", read_only=True)
    counts = {r[0]: int(r[1]) for r in rows}
    assert counts["ROUTES_TO"] == 14
    assert counts["ASSUMES_ROLE"] == 5
    assert counts["CAN_ACCESS"] == 6
    assert counts["AFFECTS"] == 4
    assert counts["IMPORTS"] == 8
    assert counts["CALLS"] == 3
    assert counts["DEPLOYS_CODE"] == 12
    assert counts["MAINTAINED"] == 12
    assert counts["TRIGGERED_ON"] == 2
    assert counts["RESOLVED_BY"] == 1
    assert counts["MODIFIED_ENTITY"] == 2


def test_indexes_present():
    rows = g.run_query(g.prod_graph(), "CALL db.indexes() YIELD label, properties, types RETURN label, properties, types", read_only=True)
    by_label = {r[0]: r[2] for r in rows}
    assert "VECTOR" in by_label["Vulnerability"]["embedding"]
    assert "FULLTEXT" in by_label["Vulnerability"]["summary"]
    assert "VECTOR" in by_label["Function"]["embedding"]
    assert "RANGE" in by_label["Service"]["name"]


def test_embeddings_have_configured_dimension():
    # size() does not accept VecF32 in FalkorDB 6, so read the vector back and measure it client-side
    rows = g.run_query(g.prod_graph(), "MATCH (v:Vulnerability {id: $id}) RETURN v.embedding", {"id": DEMO_CVE_ID}, read_only=True)
    assert len(rows[0][0]) == settings.embed_dim


def test_incidents_and_history():
    rows = g.run_query(g.prod_graph(), "MATCH (i:Incident) RETURN i.id, i.status ORDER BY i.id", read_only=True)
    assert rows == [[HISTORICAL_INCIDENT_ID, "MITIGATED"], [DEMO_INCIDENT_ID, "OPEN"]]
    rows = g.run_query(g.prod_graph(), "MATCH (r:IAMRole {name: 'ReportingReadOnly'})-[a:CAN_ACCESS]->() RETURN r.status, a.status", read_only=True)
    assert rows == [["ACTIVE", "ACTIVE"]]  # historical audit is explanatory only; live state is untouched


def test_memory_graph_seeded():
    counts = g.label_counts(g.memory_graph())
    assert counts.get("Playbook") == 1
    assert counts.get("Simulation") == 1


def test_reseed_drops_sandboxes_but_keeps_memory():
    from aegis.seed import seed_all

    sandbox = f"{settings.graph_prefix}sim_TEST"
    g.copy_graph(settings.prod_graph_name, sandbox)
    g.run_query(g.memory_graph(), "CREATE (:Playbook {signature: 'package:survives-reseed', success_count: 1, last_used: 0})")
    seed_all(reset_memory=False)
    assert not g.graph_exists(sandbox)
    rows = g.run_query(g.memory_graph(), "MATCH (p:Playbook {signature: 'package:survives-reseed'}) RETURN count(p)", read_only=True)
    assert rows[0][0] == 1
    seed_all(reset_memory=True)
    assert g.label_counts(g.memory_graph()).get("Playbook") == 1
