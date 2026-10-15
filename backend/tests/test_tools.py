from __future__ import annotations

import pytest

from aegis import graph as g
from aegis import tools
from aegis.seed import DEMO_CVE_ID, DEMO_INCIDENT_ID, HISTORICAL_INCIDENT_ID, incidents

ALERT = incidents(0)[0]["raw_alert"]
EXPECTED_EXPOSURE = 6
EXPECTED_PII_DBS = {"customer-kyc-vault-db", "global-settlement-ledger", "reporting-warehouse"}


def test_find_entry_points_anchors_the_alert():
    res = tools.find_entry_points(ALERT, top_k=3)
    assert res["best_cve_id"] == DEMO_CVE_ID
    best = res["matches"][0]
    assert best["vector_distance"] is not None and best["vector_distance"] < 0.9
    assert best["fulltext_score"] > 0
    assert [p["name"] for p in best["affected_packages"]] == ["jwt-crypto-core"]
    assert "auth-token-service" in best["entry_services"]
    assert "checkout-gateway" in best["entry_services"]  # transitive caller via CALLS
    assert res["cypher"] and res["duration_ms"] >= 0
    assert any("db.idx.vector.queryNodes" in c["cypher"] for c in res["cypher"])
    assert any("db.idx.fulltext.queryNodes" in c["cypher"] for c in res["cypher"])


def test_find_entry_points_rejects_empty():
    with pytest.raises(tools.ToolError):
        tools.find_entry_points("   ")


def test_trace_blast_radius_matches_expected_topology():
    res = tools.trace_blast_radius(DEMO_CVE_ID, max_route_hops=3)
    assert res["origin_services"] == ["auth-token-service"]
    assert res["total_paths"] == EXPECTED_EXPOSURE
    assert set(res["exposed_databases"]) == EXPECTED_PII_DBS
    for p in res["exposed_paths"]:
        assert "legacy-billing-bridge" in p["path_nodes"]
        assert p["path"]["nodes"] and p["path"]["edges"]
        assert p["total_hops"] == p["route_hops"] + 2
    pivots = {p["name"]: p for p in res["pivot_services"]}
    assert set(pivots) == {"legacy-billing-bridge", "payment-orchestrator", "reporting-adapter", "telemetry-audit-sync"}
    assert pivots["legacy-billing-bridge"]["iam_roles"] == ["LegacyBillingBridgeAdmin"]
    assert pivots["payment-orchestrator"]["tier"] == "critical"


def test_trace_blast_radius_hop_limit_and_validation():
    assert tools.trace_blast_radius(DEMO_CVE_ID, max_route_hops=1)["total_paths"] == 2
    with pytest.raises(tools.ToolError):
        tools.trace_blast_radius(DEMO_CVE_ID, max_route_hops=9)
    with pytest.raises(tools.ToolError):
        tools.trace_blast_radius("CVE-0000-0000")


def test_rank_service_criticality_uses_native_algorithms():
    res = tools.rank_service_criticality()
    assert len(res["pagerank"]) == 10 and len(res["betweenness"]) == 10
    bw = {s["service"]: s["score"] for s in res["betweenness"]}
    # hand-computed directed Brandes betweenness for the seeded mesh (docs/DESIGN.md §3.2)
    assert res["top_chokepoint"] == "legacy-billing-bridge"
    assert bw["legacy-billing-bridge"] == pytest.approx(6.0, abs=1e-3)
    assert bw["payment-orchestrator"] == pytest.approx(35 / 6, abs=1e-3)  # runner-up, but critical-tier
    assert bw["reporting-adapter"] == pytest.approx(1.0, abs=1e-3)
    assert bw["telemetry-audit-sync"] == 0.0 and bw["api-edge-gateway"] == 0.0
    assert any("algo.pageRank" in c["cypher"] for c in res["cypher"])
    assert any("algo.betweenness" in c["cypher"] for c in res["cypher"])


def test_shortest_attack_path():
    res = tools.shortest_attack_path("auth-token-service", "customer-kyc-vault-db")
    assert res["found"] and res["hop_count"] == 3 and res["active"] is True
    assert res["path_nodes"] == ["auth-token-service", "legacy-billing-bridge", "LegacyBillingBridgeAdmin", "customer-kyc-vault-db"]
    assert tools.shortest_attack_path("search-indexer", "customer-kyc-vault-db")["found"] is False


def test_expand_neighborhood_bfs():
    res = tools.expand_neighborhood("auth-token-service", depth=3)
    names = {s["name"] for s in res["reachable_services"]}
    assert names == {"legacy-billing-bridge", "payment-orchestrator", "reporting-adapter", "telemetry-audit-sync", "notification-service"}
    assert res["blast_radius_size"] == 5


def test_detect_service_communities():
    res = tools.detect_service_communities()
    assert len(res["components"]) == 1 and len(res["components"][0]["services"]) == 10
    assert sum(len(c["services"]) for c in res["communities"]) == 10


def test_find_code_owner():
    res = tools.find_code_owner(DEMO_CVE_ID)
    rec = res["recommended"]
    assert rec["handle"] == "@aarav-sec" and rec["on_call"] is True
    assert rec["package"] == "jwt-crypto-core" and rec["fixed_version"] == "2.4.2"
    assert rec["target_file"] == "src/auth/token_validator.py"


def test_recall_similar_incidents_uses_history_and_memory():
    res = tools.recall_similar_incidents(cve_id="CVE-2026-4102", package_name="legacy-sql-adapter")
    assert [p["incident_id"] for p in res["past_incidents"]] == [HISTORICAL_INCIDENT_ID]
    assert res["playbooks"][0]["signature"] == "package:legacy-sql-adapter"
    unrelated = tools.recall_similar_incidents(cve_id=DEMO_CVE_ID, package_name="jwt-crypto-core")
    assert unrelated["past_incidents"] == []
    assert [p["incident_id"] for p in unrelated["other_recent_incidents"]] == [HISTORICAL_INCIDENT_ID]


def test_simulate_refuses_critical_service(fresh_graphs):
    with pytest.raises(tools.ToolError):
        tools.simulate_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, "payment-orchestrator", "PaymentReadWriteRole")


def test_execute_refused_without_simulation(fresh_graphs):
    res = tools.execute_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, "legacy-billing-bridge", "LegacyBillingBridgeAdmin", "x" * 40)
    assert res["status"] == "REFUSED" and "simulate" in res["reason"]
    assert tools.trace_blast_radius(DEMO_CVE_ID)["total_paths"] == EXPECTED_EXPOSURE  # nothing changed


def test_full_closed_loop_simulate_execute_verify_rollback(fresh_graphs):
    sim = tools.simulate_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, "legacy-billing-bridge", "LegacyBillingBridgeAdmin")
    assert sim["exposure_before"] == EXPECTED_EXPOSURE and sim["exposure_after"] == 0
    assert sim["critical_flows_intact"] and all(f["intact"] for f in sim["critical_flows"])
    assert sim["critical_services_connected"] and sim["safe_to_execute"]
    lonely = [c for c in sim["wcc_components"] if c["services"] == ["legacy-billing-bridge"]]
    assert lonely, "the isolated bridge must become its own component"
    assert {(r["src"], r["dst"]) for r in sim["severed_routes"]} == {
        ("auth-token-service", "legacy-billing-bridge"), ("legacy-billing-bridge", "payment-orchestrator"), ("legacy-billing-bridge", "reporting-adapter")}
    assert not g.graph_exists(sim["sandbox_graph"])  # AEGIS_KEEP_SANDBOX=false in tests
    assert any("GRAPH.COPY" in c["cypher"] for c in sim["cypher"]) and any("algo.WCC" in c["cypher"] for c in sim["cypher"])
    # production untouched by the simulation
    assert tools.trace_blast_radius(DEMO_CVE_ID)["total_paths"] == EXPECTED_EXPOSURE

    action = tools.execute_remediation(DEMO_INCIDENT_ID, DEMO_CVE_ID, "legacy-billing-bridge", "LegacyBillingBridgeAdmin",
                                       "six active paths funnel through the legacy bridge; sandbox proved exposure 6 -> 0")
    assert action["status"] == "ACTION_EXECUTED"
    assert action["verification"] == {"exposed_paths_before": EXPECTED_EXPOSURE, "exposed_paths_after": 0}
    assert action["assigned_code_owner"]["handle"] == "@aarav-sec"
    assert action["pr_draft"]["title"].startswith("fix(deps): bump jwt-crypto-core 2.4.1 -> 2.4.2")
    kinds = {(m["kind"], m.get("type") or m.get("label")) for m in action["mutations"]}
    assert kinds == {("edge", "ROUTES_TO"), ("edge", "CAN_ACCESS"), ("node", "Service"), ("node", "IAMRole")}
    assert tools.trace_blast_radius(DEMO_CVE_ID)["total_paths"] == 0
    rows = g.run_query(g.prod_graph(), "MATCH (i:Incident {id: $id}) RETURN i.status", {"id": DEMO_INCIDENT_ID}, read_only=True)
    assert rows[0][0] == "MITIGATED"
    sp = tools.shortest_attack_path("auth-token-service", "customer-kyc-vault-db")
    assert sp["found"] and sp["active"] is False

    proof = tools.get_decision_proof(DEMO_INCIDENT_ID)
    assert proof["incident"]["status"] == "MITIGATED"
    assert proof["audits"][0]["id"] == action["audit_id"]
    assert len(proof["audits"][0]["proof_paths"]) == EXPECTED_EXPOSURE
    assert {e["entity"]["name"] for e in proof["audits"][0]["modified_entities"]} == {"LegacyBillingBridgeAdmin", "legacy-billing-bridge"}
    assert len(proof["proof_subgraph"]["nodes"]) >= 10

    recalled = tools.recall_similar_incidents(cve_id=DEMO_CVE_ID, package_name="jwt-crypto-core")
    assert recalled["past_incidents"][0]["audit_id"] == action["audit_id"]
    assert recalled["playbooks"][0]["signature"] == "package:jwt-crypto-core"

    rb = tools.rollback_remediation(action["audit_id"])
    assert rb["status"] == "ROLLED_BACK" and rb["incident_status"] == "OPEN"
    assert len(rb["restored"]) == len(action["mutations"])
    assert tools.trace_blast_radius(DEMO_CVE_ID)["total_paths"] == EXPECTED_EXPOSURE
    assert tools.rollback_remediation(action["audit_id"])["status"] == "ALREADY_ROLLED_BACK"
    rows = g.run_query(g.prod_graph(), "MATCH (s:Service {name: 'legacy-billing-bridge'}) RETURN s.status, s.previous_status", read_only=True)
    assert rows[0] == ["HEALTHY", None]


def test_read_graph_is_read_only():
    res = tools.read_graph("MATCH (s:Service) RETURN s.name ORDER BY s.name")
    assert res["row_count"] == 10 and res["columns"] == ["s.name"]
    assert res["cypher"][0]["cypher"].endswith("LIMIT 50")
    with pytest.raises(tools.ToolError):
        tools.read_graph("MATCH (s:Service) SET s.status = 'PWNED' RETURN s")


def test_graph_overview_and_incident_list():
    overview = tools.graph_overview()
    names = {gr["name"]: gr for gr in overview["graphs"]}
    assert names[overview["prod_graph"]]["kind"] == "prod" and names[overview["prod_graph"]]["nodes"] == 49
    incs = tools.list_incidents()
    assert [i["id"] for i in incs] == [DEMO_INCIDENT_ID, HISTORICAL_INCIDENT_ID]
    assert incs[1]["audit_count"] == 1
