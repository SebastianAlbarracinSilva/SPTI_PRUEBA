"""Capa de servicios: ejecución real de las herramientas contra PostgreSQL.

execute_secure (R5, defensa en profundidad):
  1. Vuelve a evaluar la política con la identidad autenticada (no con
     datos del LLM). Omitir el nodo supervisor de LangGraph no basta.
  2. Ejecuta con SET LOCAL ROLE agent_<rol>: PostgreSQL vuelve a negar la
     operación si el rol de BD no tiene el privilegio (tercera barrera).

execute_unsecure: lo que hace la arquitectura insegura — ejecuta lo que
pida el LLM con la conexión propietaria, sin ninguna verificación.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Callable

import psycopg

from .db import connection
from .identity import AuthContext
from .policy import TOOL_SCHEMAS, PolicyEngine

PG_ROLE = {"support": "agent_support", "admin": "agent_admin"}


class PermissionDeniedError(Exception):
    def __init__(self, rule_id: str, reason: str):
        super().__init__(f"{rule_id}: {reason}")
        self.rule_id, self.reason = rule_id, reason


def _jsonable(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        out.append({k: float(v) if isinstance(v, Decimal) else (v.isoformat() if hasattr(v, "isoformat") else v)
                    for k, v in r.items()})
    return out


# ---------------------------------------------------------------- handlers
def _query_customers(conn, auth, a) -> dict:
    rows = conn.execute(
        "SELECT id, full_name, email, phone, balance, notes FROM customers "
        "WHERE full_name ILIKE %s OR email ILIKE %s ORDER BY id LIMIT %s",
        (f"%{a['search']}%", f"%{a['search']}%", a["limit"]),
    ).fetchall()
    return {"customers": _jsonable(rows), "count": len(rows)}


def _create_ticket(conn, auth, a) -> dict:
    row = conn.execute(
        "INSERT INTO tickets (customer_id, subject, description, created_by) VALUES (%s,%s,%s,%s) RETURNING id",
        (a["customer_id"], a["subject"], a["description"], auth.username),
    ).fetchone()
    return {"ticket_id": row["id"], "status": "created"}


def _delete_customer(conn, auth, a) -> dict:
    row = conn.execute("DELETE FROM customers WHERE id=%s RETURNING id, full_name", (a["customer_id"],)).fetchone()
    return {"deleted": bool(row), "customer": _jsonable([row])[0] if row else None}


def _modify_balance(conn, auth, a) -> dict:
    row = conn.execute(
        "UPDATE customers SET balance = balance + %s WHERE id=%s RETURNING id, balance",
        (a["amount"], a["customer_id"]),
    ).fetchone()
    return {"updated": bool(row), "customer": _jsonable([row])[0] if row else None}


def _export_all_data(conn, auth, a) -> dict:
    customers = conn.execute("SELECT * FROM customers ORDER BY id").fetchall()
    tickets = conn.execute("SELECT * FROM tickets ORDER BY id").fetchall()
    return {"format": a["format"], "customers": _jsonable(customers), "tickets": _jsonable(tickets)}


def _change_agent_role(conn, auth, a) -> dict:
    row = conn.execute("UPDATE app_users SET role=%s WHERE username=%s RETURNING username, role",
                       (a["new_role"], a["username"])).fetchone()
    return {"updated": bool(row), "user": row}


HANDLERS: dict[str, Callable[[psycopg.Connection, AuthContext, dict], dict]] = {
    "query_customers": _query_customers,
    "create_ticket": _create_ticket,
    "delete_customer": _delete_customer,
    "modify_balance": _modify_balance,
    "export_all_data": _export_all_data,
    "change_agent_role": _change_agent_role,
}


# ---------------------------------------------------------------- entradas
def execute_secure(engine: PolicyEngine, auth: AuthContext, tool_name: str, args: dict) -> dict:
    result = engine.evaluate(auth.role, tool_name, args)          # barrera 2: re-verificación
    if result.decision != "ALLOW":
        raise PermissionDeniedError(result.rule_id, result.reason)
    pg_role = PG_ROLE.get(auth.role)
    if pg_role is None:
        raise PermissionDeniedError("DENY-ROLE-001", f"Sin rol de BD para {auth.role!r}")
    with connection() as conn, conn.transaction():
        conn.execute(f"SET LOCAL ROLE {pg_role}")                 # barrera 3: privilegios de PostgreSQL
        return HANDLERS[tool_name](conn, auth, result.args)


def execute_unsecure(auth: AuthContext, tool_name: str, args: dict) -> dict:
    if tool_name not in HANDLERS:
        raise ValueError(f"Herramienta desconocida: {tool_name}")
    parsed = TOOL_SCHEMAS[tool_name].model_validate(args).model_dump()  # solo para parsear tipos, no es control
    with connection() as conn, conn.transaction():
        return HANDLERS[tool_name](conn, auth, parsed)
