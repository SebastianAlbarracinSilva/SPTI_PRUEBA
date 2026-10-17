"""B01 — Benchmark de latencia del Supervisor (independiente del LLM).

Mide dos cosas:
  1. decision     : Supervisor.authorize() en memoria (lo que exige R7).
  2. decision+audit: authorize() + INSERT síncrono en audit_log (ruta completa
                     antes de ejecutar una herramienta). Requiere PostgreSQL.

Uso:  python scripts/bench_authz.py --n 5000 --n-audit 1000
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.audit import PostgresAuditSink  # noqa: E402
from app.config import ROOT, settings  # noqa: E402
from app.identity import AuthContext  # noqa: E402
from app.policy import PolicyEngine  # noqa: E402
from app.supervisor import LockoutTracker, Supervisor  # noqa: E402

CALLS = [
    ("query_customers", {"search": "Ana", "limit": 5}),
    ("create_ticket", {"customer_id": 1, "subject": "Bench", "description": "x" * 200}),
    ("delete_customer", {"customer_id": 4}),
    ("modify_balance", {"customer_id": 2, "amount": 150.5, "reason": "benchmark"}),
    ("export_all_data", {"format": "json"}),
    ("change_agent_role", {"username": "soporte1", "new_role": "admin"}),
    ("delete_customer", {"customer_id": "1 OR 1=1"}),
    ("unknown_tool", {}),
]
USERS = [AuthContext(1, "soporte1", "support"), AuthContext(3, "admin1", "admin"), AuthContext(9, "x", "guest")]


def pct(values: list[float], p: float) -> float:
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(p / 100 * len(s) + 0.5)) - 1))   # nearest-rank
    return s[k]


def summarize(name: str, values: list[float]) -> dict:
    return {"name": name, "n": len(values), "mean_ms": statistics.fmean(values), "p50_ms": pct(values, 50),
            "p95_ms": pct(values, 95), "p99_ms": pct(values, 99), "max_ms": max(values)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5000)
    ap.add_argument("--n-audit", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    rnd = random.Random(a.seed)

    engine = PolicyEngine.from_file(settings.policy_path)
    # Lockout desactivado (K=0) para que el benchmark mida siempre la evaluación completa
    sup = Supervisor(engine, timeout_ms=settings.authz_timeout_ms, lockout=LockoutTracker(0, 1, 1))
    for _ in range(200):  # calentamiento
        sup.authorize(USERS[0], *CALLS[0])

    lat, decisions = [], {"ALLOW": 0, "DENY": 0}
    for _ in range(a.n):
        user, (tool, args) = rnd.choice(USERS), rnd.choice(CALLS)
        t0 = time.perf_counter()
        d = sup.authorize(user, tool, args)
        lat.append((time.perf_counter() - t0) * 1000)
        decisions[d.decision] += 1
    results = [summarize("decision (in-memory)", lat)]

    if a.n_audit:
        try:
            sink = PostgresAuditSink()
            lat2 = []
            for i in range(a.n_audit):
                user, (tool, args) = rnd.choice(USERS), rnd.choice(CALLS)
                t0 = time.perf_counter()
                d = sup.authorize(user, tool, args)
                sink.record_decision({"trace_id": f"{i:032x}", "architecture": "benchmark", "user_id": user.user_id,
                                      "username": user.username, "user_role": user.role, "tool_name": tool,
                                      "tool_args": args, "decision": d.decision, "rule_id": d.rule_id,
                                      "reason": d.reason, "policy_version": d.policy_version,
                                      "authz_latency_ms": d.latency_ms})
                lat2.append((time.perf_counter() - t0) * 1000)
            results.append(summarize("decision + audit INSERT (PostgreSQL)", lat2))
            from app.db import connection
            with connection() as conn:
                conn.execute("DELETE FROM audit_log WHERE architecture='benchmark'")
        except Exception as exc:  # noqa: BLE001
            print(f"[aviso] sin PostgreSQL, se omite decision+audit: {exc}")

    out = {"benchmark": "B01", "policy_version": engine.version, "decisions": decisions, "target_p95_ms": 50,
           "results": results, "python": sys.version.split()[0]}
    path = ROOT / "reports" / "b01_latency.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(f"\nB01 — latencia de autorización (objetivo p95 < 50 ms)  decisiones={decisions}\n")
    print("| Medición | n | p50 (ms) | p95 (ms) | p99 (ms) | máx (ms) | ¿p95 < 50 ms? |")
    print("|---|---|---|---|---|---|---|")
    for r in results:
        print(f"| {r['name']} | {r['n']} | {r['p50_ms']:.4f} | {r['p95_ms']:.4f} | {r['p99_ms']:.4f} | "
              f"{r['max_ms']:.3f} | {'SÍ' if r['p95_ms'] < 50 else 'NO'} |")
    print(f"\nGuardado en {path}")


if __name__ == "__main__":
    main()
