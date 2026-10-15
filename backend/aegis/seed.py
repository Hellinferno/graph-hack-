"""Seeds the AegisGraph demo topology into FalkorDB (see docs/DESIGN.md §3).

The dataset is synthetic (hackathon data policy) and deterministic: codebase layer (CVEs, packages,
functions, developers), runtime layer (services, routes), identity layer (IAM roles, databases) and
operational layer (incidents, a historical audit). ``seed_all()`` rebuilds ``<prefix>prod_graph`` and
initialises ``<prefix>memory_graph`` with one playbook learned from the historical incident.

Run: ``python -m aegis seed`` (from backend/) or ``python -m aegis.seed``.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from redis.exceptions import ResponseError

from . import graph as g
from .config import settings
from .embeddings import embed

log = logging.getLogger("aegis.seed")

# --------------------------------------------------------------------------------------
# Dataset
# --------------------------------------------------------------------------------------

SERVICES: list[dict[str, Any]] = [
    {"id": "svc-api-edge-gateway", "name": "api-edge-gateway", "tier": "critical", "rps": 14200},
    {"id": "svc-auth-token-service", "name": "auth-token-service", "tier": "critical", "rps": 9800},
    {"id": "svc-checkout-gateway", "name": "checkout-gateway", "tier": "critical", "rps": 5400},
    {"id": "svc-payment-orchestrator", "name": "payment-orchestrator", "tier": "critical", "rps": 3100},
    {"id": "svc-inventory-service", "name": "inventory-service", "tier": "critical", "rps": 2600},
    {"id": "svc-notification-service", "name": "notification-service", "tier": "standard", "rps": 900},
    {"id": "svc-telemetry-audit-sync", "name": "telemetry-audit-sync", "tier": "standard", "rps": 1200},
    {"id": "svc-legacy-billing-bridge", "name": "legacy-billing-bridge", "tier": "standard", "rps": 180},
    {"id": "svc-reporting-adapter", "name": "reporting-adapter", "tier": "standard", "rps": 240},
    {"id": "svc-search-indexer", "name": "search-indexer", "tier": "standard", "rps": 700},
]

# (src, dst, is_critical_path, protocol)
ROUTES: list[tuple[str, str, bool, str]] = [
    ("api-edge-gateway", "auth-token-service", True, "grpc"),
    ("api-edge-gateway", "checkout-gateway", True, "http"),
    ("api-edge-gateway", "search-indexer", False, "http"),
    ("checkout-gateway", "auth-token-service", True, "grpc"),
    ("checkout-gateway", "payment-orchestrator", True, "grpc"),
    ("checkout-gateway", "inventory-service", True, "grpc"),
    ("payment-orchestrator", "telemetry-audit-sync", False, "kafka"),
    ("payment-orchestrator", "notification-service", False, "http"),
    ("auth-token-service", "legacy-billing-bridge", False, "http"),
    ("legacy-billing-bridge", "payment-orchestrator", False, "http"),
    ("legacy-billing-bridge", "reporting-adapter", False, "http"),
    ("inventory-service", "telemetry-audit-sync", False, "kafka"),
    ("reporting-adapter", "telemetry-audit-sync", False, "kafka"),
    ("search-indexer", "inventory-service", False, "grpc"),
]

IAM_ROLES: list[dict[str, Any]] = [
    {"name": "LegacyBillingBridgeAdmin", "privilege_level": "ADMIN"},
    {"name": "PaymentReadWriteRole", "privilege_level": "SCOPED"},
    {"name": "ReportingReadOnly", "privilege_level": "READONLY"},
    {"name": "InventoryWriter", "privilege_level": "SCOPED"},
]
for _r in IAM_ROLES:
    _r["arn"] = f"arn:aws:iam::992100:role/{_r['name']}"
    _r["status"] = "ACTIVE"

# (service, role, scope)
ASSUMES: list[tuple[str, str, str]] = [
    ("legacy-billing-bridge", "LegacyBillingBridgeAdmin", "account"),
    ("payment-orchestrator", "PaymentReadWriteRole", "ledger"),
    ("telemetry-audit-sync", "PaymentReadWriteRole", "metrics"),
    ("reporting-adapter", "ReportingReadOnly", "warehouse"),
    ("inventory-service", "InventoryWriter", "catalog"),
]

DATABASES: list[dict[str, Any]] = [
    {"id": "db-cust-pii", "name": "customer-kyc-vault-db", "contains_pii": True, "classification": "RESTRICTED_PII"},
    {"id": "db-ledger", "name": "global-settlement-ledger", "contains_pii": True, "classification": "FINANCIAL_CORE"},
    {"id": "db-reporting", "name": "reporting-warehouse", "contains_pii": True, "classification": "INTERNAL_ANALYTICS"},
    {"id": "db-metrics", "name": "prometheus-archive-store", "contains_pii": False, "classification": "INTERNAL_TELEMETRY"},
    {"id": "db-catalog", "name": "product-catalog-db", "contains_pii": False, "classification": "INTERNAL"},
]

# (role, database, access_mode)
CAN_ACCESS: list[tuple[str, str, str]] = [
    ("LegacyBillingBridgeAdmin", "customer-kyc-vault-db", "ADMIN"),
    ("LegacyBillingBridgeAdmin", "global-settlement-ledger", "ADMIN"),
    ("PaymentReadWriteRole", "global-settlement-ledger", "WRITE"),
    ("PaymentReadWriteRole", "prometheus-archive-store", "WRITE"),
    ("ReportingReadOnly", "reporting-warehouse", "READ"),
    ("InventoryWriter", "product-catalog-db", "WRITE"),
]

PACKAGES: list[dict[str, Any]] = [
    {"name": "jwt-crypto-core", "version": "2.4.1", "fixed_version": "2.4.2", "ecosystem": "pip"},
    {"name": "legacy-sql-adapter", "version": "0.9.3", "fixed_version": "1.0.0", "ecosystem": "pip"},
    {"name": "yaml-loader", "version": "5.1.0", "fixed_version": "5.4.1", "ecosystem": "pip"},
    {"name": "image-resizer", "version": "1.2.0", "fixed_version": "1.2.3", "ecosystem": "npm"},
    {"name": "redis-session-pool", "version": "1.9.0", "fixed_version": "1.9.0", "ecosystem": "pip"},
    {"name": "http-retry", "version": "3.0.0", "fixed_version": "3.0.0", "ecosystem": "npm"},
]

VULNERABILITIES: list[dict[str, Any]] = [
    {
        "id": "CVE-2026-8841", "severity": "CRITICAL", "cvss": 9.8, "published": "2026-10-13",
        "summary": "Remote token forgery and deserialization bypass in jwt-crypto-core allows unauthenticated "
                   "attackers to mint valid bearer tokens",
        "package": "jwt-crypto-core", "exploitability": "HIGH",
    },
    {
        "id": "CVE-2026-4102", "severity": "HIGH", "cvss": 8.1, "published": "2026-10-01",
        "summary": "SQL injection in legacy-sql-adapter reporting query builder",
        "package": "legacy-sql-adapter", "exploitability": "MEDIUM",
    },
    {
        "id": "CVE-2026-2210", "severity": "HIGH", "cvss": 7.5, "published": "2026-09-20",
        "summary": "Unsafe YAML deserialization in yaml-loader leads to remote code execution",
        "package": "yaml-loader", "exploitability": "MEDIUM",
    },
    {
        "id": "CVE-2026-0193", "severity": "MEDIUM", "cvss": 5.3, "published": "2026-08-30",
        "summary": "Denial of service via crafted PNG in image-resizer",
        "package": "image-resizer", "exploitability": "LOW",
    },
]

FUNCTIONS: list[dict[str, Any]] = [
    {"id": "fn_verify_bearer_token", "name": "verify_bearer_token()", "file_path": "src/auth/token_validator.py", "repo_name": "core-auth-service", "imports": [("jwt-crypto-core", 42)], "calls": []},
    {"id": "fn_issue_session_token", "name": "issue_session_token()", "file_path": "src/auth/session_issuer.py", "repo_name": "core-auth-service", "imports": [("jwt-crypto-core", 17), ("redis-session-pool", 18)], "calls": []},
    {"id": "fn_validate_checkout_session", "name": "validate_checkout_session()", "file_path": "src/checkout/session_guard.py", "repo_name": "checkout-gateway", "imports": [], "calls": [("fn_verify_bearer_token", "HIGH")]},
    {"id": "fn_settle_merchant_payout", "name": "settle_merchant_payout()", "file_path": "src/ledger/payout_worker.py", "repo_name": "payment-orchestrator", "imports": [], "calls": [("fn_validate_checkout_session", "MEDIUM")]},
    {"id": "fn_reconcile_legacy_invoices", "name": "reconcile_legacy_invoices()", "file_path": "src/billing/reconcile.py", "repo_name": "legacy-billing-bridge", "imports": [("legacy-sql-adapter", 9)], "calls": []},
    {"id": "fn_build_report", "name": "build_report()", "file_path": "src/reports/builder.py", "repo_name": "reporting-adapter", "imports": [("legacy-sql-adapter", 12)], "calls": []},
    {"id": "fn_parse_config", "name": "parse_config()", "file_path": "src/config/loader.py", "repo_name": "search-indexer", "imports": [("yaml-loader", 3)], "calls": []},
    {"id": "fn_index_products", "name": "index_products()", "file_path": "src/index/products.py", "repo_name": "search-indexer", "imports": [], "calls": [("fn_parse_config", "LOW")]},
    {"id": "fn_resize_avatar", "name": "resize_avatar()", "file_path": "src/media/avatar.ts", "repo_name": "notification-service", "imports": [("image-resizer", 5)], "calls": []},
    {"id": "fn_retry_dispatch", "name": "retry_dispatch()", "file_path": "src/dispatch/retry.ts", "repo_name": "notification-service", "imports": [("http-retry", 2)], "calls": []},
    {"id": "fn_sync_metrics", "name": "sync_metrics()", "file_path": "src/metrics/sync.py", "repo_name": "telemetry-audit-sync", "imports": [], "calls": []},
    {"id": "fn_reserve_stock", "name": "reserve_stock()", "file_path": "src/stock/reserve.py", "repo_name": "inventory-service", "imports": [], "calls": []},
]

# (service, function id, commit sha)
DEPLOYS: list[tuple[str, str, str]] = [
    ("auth-token-service", "fn_verify_bearer_token", "a1f3c9e"),
    ("auth-token-service", "fn_issue_session_token", "a1f3c9e"),
    ("checkout-gateway", "fn_validate_checkout_session", "7b2d410"),
    ("payment-orchestrator", "fn_settle_merchant_payout", "c0ffee1"),
    ("legacy-billing-bridge", "fn_reconcile_legacy_invoices", "deadb33"),
    ("reporting-adapter", "fn_build_report", "9e8d7c6"),
    ("search-indexer", "fn_parse_config", "5a5a5a5"),
    ("search-indexer", "fn_index_products", "5a5a5a5"),
    ("notification-service", "fn_resize_avatar", "0b0b0b0"),
    ("notification-service", "fn_retry_dispatch", "0b0b0b0"),
    ("telemetry-audit-sync", "fn_sync_metrics", "1c1c1c1"),
    ("inventory-service", "fn_reserve_stock", "2d2d2d2"),
]

DEVELOPERS: list[dict[str, Any]] = [
    {"id": "dev-01", "name": "Aarav Mehta", "handle": "@aarav-sec", "team": "Identity & Core Auth", "on_call": True,
     "maintains": [("fn_verify_bearer_token", 84, "2026-10-10"), ("fn_issue_session_token", 52, "2026-10-06")]},
    {"id": "dev-02", "name": "Priya Nair", "handle": "@priya-payments", "team": "Checkout & Ledger", "on_call": False,
     "maintains": [("fn_validate_checkout_session", 61, "2026-10-12"), ("fn_settle_merchant_payout", 49, "2026-10-08")]},
    {"id": "dev-03", "name": "Rohan Iyer", "handle": "@rohan-platform", "team": "Platform", "on_call": True,
     "maintains": [("fn_reconcile_legacy_invoices", 33, "2026-09-28"), ("fn_build_report", 27, "2026-10-02"), ("fn_sync_metrics", 19, "2026-09-15")]},
    {"id": "dev-04", "name": "Meera Krishnan", "handle": "@meera-infra", "team": "Infrastructure", "on_call": False,
     "maintains": [("fn_parse_config", 41, "2026-10-09"), ("fn_index_products", 38, "2026-10-11"), ("fn_retry_dispatch", 12, "2026-08-21")]},
    {"id": "dev-05", "name": "Dev Patel", "handle": "@dev-growth", "team": "Growth", "on_call": False,
     "maintains": [("fn_resize_avatar", 22, "2026-09-30"), ("fn_reserve_stock", 30, "2026-10-07")]},
]

DEMO_INCIDENT_ID = "INC-2026-091"
DEMO_CVE_ID = "CVE-2026-8841"
HISTORICAL_INCIDENT_ID = "INC-2026-077"
HISTORICAL_AUDIT_ID = "AUDIT-SEED-077"

CRITICAL_FLOWS: list[tuple[str, str]] = [
    ("api-edge-gateway", "auth-token-service"),
    ("api-edge-gateway", "checkout-gateway"),
    ("checkout-gateway", "payment-orchestrator"),
    ("checkout-gateway", "inventory-service"),
]


def incidents(now: int) -> list[dict[str, Any]]:
    return [
        {
            "id": DEMO_INCIDENT_ID, "timestamp": now, "status": "OPEN", "cve": DEMO_CVE_ID, "confidence": 0.93,
            "title": "Anomalous JWT token forgery attempt targeting api-edge-gateway",
            "raw_alert": "WAF observed 1,240 bearer tokens with forged kid headers accepted by auth-token-service in "
                         "4 minutes; signature verification bypass suspected in jwt-crypto-core (deserialization path)",
        },
        {
            "id": HISTORICAL_INCIDENT_ID, "timestamp": now - 9 * 86400, "status": "MITIGATED", "cve": "CVE-2026-4102",
            "confidence": 0.81,
            "title": "SQLi probe against reporting-adapter via legacy-sql-adapter",
            "raw_alert": "Repeated UNION SELECT payloads observed against the reporting query builder; "
                         "legacy-sql-adapter 0.9.3 vulnerable to CVE-2026-4102",
        },
    ]


# --------------------------------------------------------------------------------------
# Index + graph construction
# --------------------------------------------------------------------------------------

PROD_INDEXES: list[str] = [
    "CREATE INDEX FOR (v:Vulnerability) ON (v.id)",
    "CREATE INDEX FOR (p:Package) ON (p.name)",
    "CREATE INDEX FOR (f:Function) ON (f.id)",
    "CREATE INDEX FOR (s:Service) ON (s.id)",
    "CREATE INDEX FOR (s:Service) ON (s.name)",
    "CREATE INDEX FOR (r:IAMRole) ON (r.name)",
    "CREATE INDEX FOR (d:Database) ON (d.name)",
    "CREATE INDEX FOR (dev:Developer) ON (dev.handle)",
    "CREATE INDEX FOR (i:Incident) ON (i.id)",
    "CREATE INDEX FOR (a:ActionAudit) ON (a.id)",
    "CREATE VECTOR INDEX FOR (v:Vulnerability) ON (v.embedding) OPTIONS {dimension: $dim, similarityFunction: 'cosine', M: 16, efConstruction: 200}",
    "CREATE VECTOR INDEX FOR (f:Function) ON (f.embedding) OPTIONS {dimension: $dim, similarityFunction: 'cosine', M: 16, efConstruction: 200}",
    "CREATE FULLTEXT INDEX FOR (v:Vulnerability) ON (v.summary)",
]

MEMORY_INDEXES: list[str] = [
    "CREATE INDEX FOR (e:Episode) ON (e.id)",
    "CREATE INDEX FOR (e:Episode) ON (e.incident_id)",
    "CREATE INDEX FOR (s:Simulation) ON (s.id)",
    "CREATE INDEX FOR (s:Simulation) ON (s.incident_id)",
    "CREATE INDEX FOR (p:Playbook) ON (p.signature)",
    "CREATE INDEX FOR (t:ToolCall) ON (t.id)",
]


def create_indexes(graph, statements: list[str]) -> int:
    """Create indexes, ignoring 'already indexed' errors. Returns the number created."""
    created = 0
    for stmt in statements:
        try:
            graph.query(stmt.replace("$dim", str(settings.embed_dim)))
            created += 1
        except ResponseError as exc:
            if "already indexed" in str(exc).lower() or "already exists" in str(exc).lower():
                continue
            raise
    return created


def seed_prod_graph(reset: bool = True, now: int | None = None) -> dict[str, int]:
    """Build the production topology graph. Returns label counts."""
    now = now or int(time.time())
    name = settings.prod_graph_name
    if reset:
        g.delete_graph_if_exists(name)
    graph = g.get_db().select_graph(name)
    create_indexes(graph, PROD_INDEXES)

    q = graph.query

    q("UNWIND $rows AS row CREATE (:Service {id: row.id, name: row.name, tier: row.tier, status: 'HEALTHY', rps: row.rps})",
      params={"rows": SERVICES})
    q("UNWIND $rows AS row CREATE (:IAMRole {arn: row.arn, name: row.name, privilege_level: row.privilege_level, status: row.status})",
      params={"rows": IAM_ROLES})
    q("UNWIND $rows AS row CREATE (:Database {id: row.id, name: row.name, contains_pii: row.contains_pii, classification: row.classification})",
      params={"rows": DATABASES})
    q("UNWIND $rows AS row CREATE (:Package {name: row.name, version: row.version, fixed_version: row.fixed_version, ecosystem: row.ecosystem})",
      params={"rows": PACKAGES})
    vuln_rows = [
        {"id": v["id"], "severity": v["severity"], "cvss": v["cvss"], "summary": v["summary"], "published": v["published"],
         "embedding": embed(f"{v['id']} {v['summary']} {v['package']}")}
        for v in VULNERABILITIES
    ]
    q("UNWIND $rows AS row CREATE (:Vulnerability {id: row.id, severity: row.severity, cvss: row.cvss, summary: row.summary, "
      "published: row.published, embedding: vecf32(row.embedding)})", params={"rows": vuln_rows})
    fn_rows = [
        {"id": f["id"], "name": f["name"], "file_path": f["file_path"], "repo_name": f["repo_name"],
         "embedding": embed(f"{f['name']} {f['file_path']} {f['repo_name']}")}
        for f in FUNCTIONS
    ]
    q("UNWIND $rows AS row CREATE (:Function {id: row.id, name: row.name, file_path: row.file_path, repo_name: row.repo_name, "
      "embedding: vecf32(row.embedding)})", params={"rows": fn_rows})
    q("UNWIND $rows AS row CREATE (:Developer {id: row.id, name: row.name, handle: row.handle, team: row.team, on_call: row.on_call})",
      params={"rows": [{k: v for k, v in d.items() if k != "maintains"} for d in DEVELOPERS]})
    q("UNWIND $rows AS row CREATE (:Incident {id: row.id, timestamp: row.timestamp, title: row.title, raw_alert: row.raw_alert, status: row.status})",
      params={"rows": [{k: v for k, v in i.items() if k not in ("cve", "confidence")} for i in incidents(now)]})

    # ---- relationships ----
    q("UNWIND $rows AS row MATCH (a:Service {name: row.src}), (b:Service {name: row.dst}) "
      "CREATE (a)-[:ROUTES_TO {status: 'ACTIVE', is_critical_path: row.crit, protocol: row.protocol}]->(b)",
      params={"rows": [{"src": s, "dst": d, "crit": c, "protocol": p} for s, d, c, p in ROUTES]})
    q("UNWIND $rows AS row MATCH (s:Service {name: row.svc}), (r:IAMRole {name: row.role}) "
      "CREATE (s)-[:ASSUMES_ROLE {scope: row.scope}]->(r)",
      params={"rows": [{"svc": s, "role": r, "scope": sc} for s, r, sc in ASSUMES]})
    q("UNWIND $rows AS row MATCH (r:IAMRole {name: row.role}), (d:Database {name: row.db}) "
      "CREATE (r)-[:CAN_ACCESS {status: 'ACTIVE', access_mode: row.mode}]->(d)",
      params={"rows": [{"role": r, "db": d, "mode": m} for r, d, m in CAN_ACCESS]})
    q("UNWIND $rows AS row MATCH (v:Vulnerability {id: row.cve}), (p:Package {name: row.pkg}) "
      "CREATE (v)-[:AFFECTS {exploitability: row.exploitability}]->(p)",
      params={"rows": [{"cve": v["id"], "pkg": v["package"], "exploitability": v["exploitability"]} for v in VULNERABILITIES]})
    q("UNWIND $rows AS row MATCH (f:Function {id: row.fn}), (p:Package {name: row.pkg}) "
      "CREATE (f)-[:IMPORTS {line_number: row.line}]->(p)",
      params={"rows": [{"fn": f["id"], "pkg": pkg, "line": line} for f in FUNCTIONS for pkg, line in f["imports"]]})
    q("UNWIND $rows AS row MATCH (a:Function {id: row.src}), (b:Function {id: row.dst}) "
      "CREATE (a)-[:CALLS {call_frequency: row.freq}]->(b)",
      params={"rows": [{"src": f["id"], "dst": dst, "freq": freq} for f in FUNCTIONS for dst, freq in f["calls"]]})
    q("UNWIND $rows AS row MATCH (s:Service {name: row.svc}), (f:Function {id: row.fn}) "
      "CREATE (s)-[:DEPLOYS_CODE {commit_sha: row.sha}]->(f)",
      params={"rows": [{"svc": s, "fn": fn, "sha": sha} for s, fn, sha in DEPLOYS]})
    q("UNWIND $rows AS row MATCH (d:Developer {id: row.dev}), (f:Function {id: row.fn}) "
      "CREATE (d)-[:MAINTAINED {commits_count: row.commits, last_touched: row.touched}]->(f)",
      params={"rows": [{"dev": d["id"], "fn": fn, "commits": c, "touched": t} for d in DEVELOPERS for fn, c, t in d["maintains"]]})
    q("UNWIND $rows AS row MATCH (i:Incident {id: row.id}), (v:Vulnerability {id: row.cve}) "
      "CREATE (i)-[:TRIGGERED_ON {detected_at: row.timestamp, confidence: row.confidence}]->(v)",
      params={"rows": [{"id": i["id"], "cve": i["cve"], "timestamp": i["timestamp"], "confidence": i["confidence"]} for i in incidents(now)]})

    # ---- historical, already-mitigated incident with its explainable audit trail (episodic memory) ----
    q("""
    MATCH (inc:Incident {id: $incident_id}), (role:IAMRole {name: 'ReportingReadOnly'}), (svc:Service {name: 'reporting-adapter'})
    CREATE (a:ActionAudit {
        id: $audit_id, timestamp: $ts, action_type: 'SURGICAL_ROLE_QUARANTINE_AND_OWNER_PR',
        target_entity: 'ReportingReadOnly -> reporting-warehouse', bridge_service: 'reporting-adapter', iam_role: 'ReportingReadOnly',
        betweenness_score: 1.0, pagerank_score: 0.061, sim_passed: true, simulation_id: 'SIM-SEED-077',
        cypher_proof: '[]', proof_paths: $proof_paths, mutations: '[]',
        assigned_developer: '@rohan-platform', pr_url: 'pending://github/reporting-adapter/pull/aegis-cve-2026-4102',
        justification: 'reporting-adapter was the only standard-tier pivot between the SQLi entry point and reporting-warehouse (PII); sandbox WCC check kept all critical flows connected.',
        rolled_back: false, mode: 'deterministic'
    })
    CREATE (inc)-[:RESOLVED_BY {execution_time_ms: 412}]->(a)
    CREATE (a)-[:MODIFIED_ENTITY {previous_state: 'ACTIVE', new_state: 'QUARANTINED', entity_kind: 'IAMRole'}]->(role)
    CREATE (a)-[:MODIFIED_ENTITY {previous_state: 'HEALTHY', new_state: 'ISOLATED', entity_kind: 'Service'}]->(svc)
    """, params={
        "incident_id": HISTORICAL_INCIDENT_ID, "audit_id": HISTORICAL_AUDIT_ID, "ts": now - 9 * 86400 + 600,
        "proof_paths": '[{"path_nodes": ["reporting-adapter", "ReportingReadOnly", "reporting-warehouse"], "route_hops": 0}]',
    })

    counts = g.label_counts(graph)
    log.info("seeded %s: %s", name, counts)
    return counts


def seed_memory_graph(reset: bool = True, now: int | None = None) -> dict[str, int]:
    """Initialise the memory graph with indexes and one playbook learned from the historical incident."""
    now = now or int(time.time())
    name = settings.memory_graph_name
    if reset:
        g.delete_graph_if_exists(name)
    graph = g.get_db().select_graph(name)
    create_indexes(graph, MEMORY_INDEXES)
    graph.query("""
    MERGE (p:Playbook {signature: 'package:legacy-sql-adapter'})
    SET p.action_type = 'SURGICAL_ROLE_QUARANTINE_AND_OWNER_PR', p.bridge_service = 'reporting-adapter',
        p.iam_role = 'ReportingReadOnly', p.success_count = 1, p.last_used = $ts, p.last_incident_id = $incident_id
    MERGE (s:Simulation {id: 'SIM-SEED-077'})
    SET s.incident_id = $incident_id, s.cve_id = 'CVE-2026-4102', s.timestamp = $ts, s.bridge_service = 'reporting-adapter',
        s.iam_role = 'ReportingReadOnly', s.safe = true, s.exposure_closed = true, s.critical_flows_intact = true,
        s.critical_services_connected = true, s.sandbox_graph = 'seed', s.exposure_before = 1, s.exposure_after = 0
    MERGE (p)-[:DERIVED_FROM]->(s)
    """, params={"ts": now - 9 * 86400 + 500, "incident_id": HISTORICAL_INCIDENT_ID})
    counts = g.label_counts(graph)
    log.info("seeded %s: %s", name, counts)
    return counts


def drop_sandboxes() -> list[str]:
    """Delete every counterfactual sandbox graph (``<prefix>sim_*``); they are disposable by design."""
    prefix = f"{settings.graph_prefix}sim_"
    dropped = [name for name in g.list_graphs() if name.startswith(prefix)]
    for name in dropped:
        g.delete_graph_if_exists(name)
    return dropped


def seed_all(reset_memory: bool = False) -> dict[str, dict[str, int]]:
    """Rebuild production and drop sandboxes. Memory survives unless ``reset_memory`` (cross-session learning)."""
    now = int(time.time())
    drop_sandboxes()
    prod = seed_prod_graph(reset=True, now=now)
    memory = seed_memory_graph(reset=reset_memory, now=now)
    return {"prod": prod, "memory": memory}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    result = seed_all()
    log.info("done: %s", result)
