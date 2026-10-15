"""Records a real session from the running AegisGraph API into frontend/public/mock-fixture.json.

The console's `?mock=1` mode replays this file, so the preview shows exactly what the real system produced
(graph snapshots before/after, the sandbox graph, every run event with its timing, memory, rollback).

Prerequisites: FalkorDB up and the API running on http://127.0.0.1:8000 (`python -m aegis api`).
Usage (from the project root):  .venv/Scripts/python.exe scripts/record_mock_fixture.py
WARNING: this reseeds the demo graphs (memory is reset, then one warm-up run is made so recall has a playbook).
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import httpx

API = "http://127.0.0.1:8000/api"
INCIDENT = "INC-2026-091"
OUT = Path(__file__).resolve().parent.parent / "frontend" / "public" / "mock-fixture.json"


def wait_run(client: httpx.Client, run_id: str) -> dict:
    deadline = time.time() + 120
    while time.time() < deadline:
        rec = client.get(f"{API}/runs/{run_id}").json()
        if rec["status"] != "running":
            return rec
        time.sleep(0.3)
    raise RuntimeError(f"run {run_id} did not finish")


def main() -> int:
    with httpx.Client(timeout=60) as c:
        if c.get(f"{API}/health").status_code != 200:
            print("API/FalkorDB not healthy; start them first", file=sys.stderr)
            return 1
        # clean slate, then one warm-up run so the recorded run recalls a learned playbook (cross-session memory)
        c.post(f"{API}/seed", json={"reset_memory": True}).raise_for_status()
        warm = c.post(f"{API}/runs", json={"incident_id": INCIDENT, "mode": "deterministic"}).json()
        wait_run(c, warm["run_id"])
        seed = c.post(f"{API}/seed", json={"reset_memory": False}).json()

        before = {
            "health": c.get(f"{API}/health").json(),
            "incidents": c.get(f"{API}/incidents").json(),
            "graph": c.get(f"{API}/graph").json(),
            "graphs": c.get(f"{API}/graphs").json(),
            "memory": c.get(f"{API}/memory").json(),
            "proof": c.get(f"{API}/incidents/{INCIDENT}").json(),
        }
        tools = c.get(f"{API}/tools").json()
        run = c.post(f"{API}/runs", json={"incident_id": INCIDENT, "mode": "deterministic"}).json()
        record = wait_run(c, run["run_id"])
        events = record["events"]
        done = next(e for e in events if e["type"] == "run_completed")
        sim = next(e["result"] for e in events if e["type"] == "tool_result" and e["name"] == "simulate_remediation")
        after = {
            "health": c.get(f"{API}/health").json(),
            "incidents": c.get(f"{API}/incidents").json(),
            "graph": c.get(f"{API}/graph").json(),
            "graphs": c.get(f"{API}/graphs").json(),
            "memory": c.get(f"{API}/memory").json(),
            "proof": c.get(f"{API}/incidents/{INCIDENT}").json(),
        }
        sandbox = c.get(f"{API}/graph/{sim['sandbox_graph']}").json()
        rollback = c.post(f"{API}/rollback/{done['audit_id']}").json()
        # rollback restores statuses but keeps the (rolled_back) audit node, so record that state too
        restored = {
            "health": c.get(f"{API}/health").json(),
            "incidents": c.get(f"{API}/incidents").json(),
            "graph": c.get(f"{API}/graph").json(),
            "graphs": c.get(f"{API}/graphs").json(),
            "memory": c.get(f"{API}/memory").json(),
            "proof": c.get(f"{API}/incidents/{INCIDENT}").json(),
        }
        # leave the demo ready to run again
        c.post(f"{API}/seed", json={"reset_memory": False}).raise_for_status()

    fixture = {
        "recorded_at": int(time.time()),
        "note": "Recorded from a live AegisGraph session by scripts/record_mock_fixture.py; replayed by ?mock=1.",
        "seed": seed,
        "tools": tools,
        "before": before,
        "after": after,
        "sandbox_graph": sim["sandbox_graph"],
        "sandbox": sandbox,
        "run": {"run_id": record["run_id"], "mode": record["mode"], "events": events},
        "audit_id": done["audit_id"],
        "rollback": rollback,
        "restored": restored,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixture, separators=(",", ":"), default=str), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB, {len(events)} events, audit {done['audit_id']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
