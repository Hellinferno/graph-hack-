from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from aegis.api import app
from aegis.seed import DEMO_CVE_ID, DEMO_INCIDENT_ID, HISTORICAL_INCIDENT_ID


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["falkordb"] is True and body["seeded"] is True
    assert body["llm_configured"] is False and body["mcp_servers"] == ["aegisgraph"]
    assert body["label_counts"]["Service"] == 10
    assert body["falkordb_browser_url"].startswith("http://")


def test_tools_and_graph_endpoints(client):
    names = {t["name"] for t in client.get("/api/tools").json()}
    assert len(names) == 13 and "simulate_remediation" in names
    snap = client.get("/api/graph").json()
    assert len(snap["nodes"]) == 49 and len(snap["edges"]) == 69
    assert client.get("/api/graph/not_prefixed").status_code == 400
    assert client.get("/api/graph/test_aegis_nope").status_code == 404
    incs = client.get("/api/incidents").json()
    assert [i["id"] for i in incs] == [DEMO_INCIDENT_ID, HISTORICAL_INCIDENT_ID]
    assert client.get(f"/api/incidents/{HISTORICAL_INCIDENT_ID}").json()["audits"][0]["id"] == "AUDIT-SEED-077"
    assert client.get("/api/incidents/INC-0").status_code == 404
    direct = client.post("/api/tools/trace_blast_radius", json={"cve_id": DEMO_CVE_ID}).json()
    assert direct["result"]["total_paths"] == 6 and direct["server"] == "aegisgraph"
    assert client.post("/api/tools/nope", json={}).status_code == 404


def test_run_lifecycle_and_sse(client, fresh_graphs):
    assert client.post("/api/runs", json={"incident_id": DEMO_INCIDENT_ID, "mode": "llm"}).status_code == 400
    created = client.post("/api/runs", json={"incident_id": DEMO_INCIDENT_ID, "mode": "auto"}).json()
    assert created["mode"] == "deterministic"
    run_id = created["run_id"]
    deadline = time.time() + 120
    while time.time() < deadline:
        rec = client.get(f"/api/runs/{run_id}").json()
        if rec["status"] != "running":
            break
        time.sleep(0.5)
    assert rec["status"] == "completed", rec["events"][-3:]
    done = rec["events"][-1]
    assert done["type"] == "run_completed" and done["outcome"] == "MITIGATED" and done["audit_id"]

    sse = client.get(f"/api/runs/{run_id}/events")
    assert sse.headers["content-type"].startswith("text/event-stream")
    assert "event: run_started" in sse.text and "event: run_completed" in sse.text and sse.text.rstrip().endswith("data: {}")
    assert run_id in [r["run_id"] for r in client.get("/api/runs").json()]

    mem = client.get("/api/memory").json()
    assert any(e["id"] == done["episode_id"] for e in mem["episodes"])

    rb = client.post(f"/api/rollback/{done['audit_id']}").json()
    assert rb["status"] == "ROLLED_BACK"
    assert client.post("/api/rollback/AUDIT-NOPE").status_code == 400
    assert client.get("/api/runs/run-nope").status_code == 404


def test_seed_endpoint(client):
    body = client.post("/api/seed", json={"reset_memory": False}).json()
    assert body["prod"]["Service"] == 10
